/*
 * Copyright 2020 Google LLC
 * Copyright 2026 StepSecurity
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import fs from 'fs';
import path from 'path';

import * as core from '@actions/core';
import {
  addPath,
  debug as logDebug,
  getInput,
  info as logInfo,
  setFailed,
  setOutput,
  warning as logWarning,
} from '@actions/core';
import { getExecOutput } from '@actions/exec';
import * as toolCache from '@actions/tool-cache';
import { readFile } from 'fs/promises';
import { parse as parseYAML } from 'yaml';

import {
  errorMessage,
  isPinnedToHead,
  joinKVStringForGCloud,
  KVPair,
  parseBoolean,
  parseCSV,
  parseFlags,
  parseKVString,
  parseKVStringAndFile,
  pinnedToHeadWarning,
  presence,
} from '@google-github-actions/actions-utils';
import {
  authenticateGcloudSDK,
  getLatestGcloudSDKVersion,
  getToolCommand,
  installComponent as installGcloudComponent,
  installGcloudSDK,
  isInstalled as isGcloudInstalled,
} from '@google-github-actions/setup-cloud-sdk';

import { parseDeployResponse, parseUpdateTrafficResponse } from './output-parser';
import axios, { isAxiosError } from 'axios';

// Do not listen to the linter - this can NOT be rewritten as an ES6 import
// statement.
const { version: appVersion } = require('../package.json');

// isDebug returns true if runner debugging or step debugging is enabled.
const isDebug =
  parseBoolean(process.env.ACTIONS_RUNNER_DEBUG) || parseBoolean(process.env.ACTIONS_STEP_DEBUG);

/**
 * DeployCloudRunOutputs are the common GitHub action outputs created by this action
 */
export interface DeployCloudRunOutputs {
  url?: string | null | undefined; // Type required to match run_v1.Schema$Service.status.url
}

/**
 * ResponseTypes are the gcloud command response formats
 */
enum ResponseTypes {
  DEPLOY,
  UPDATE_TRAFFIC,
}

async function validateSubscription() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  let repoPrivate: boolean | undefined;

  if (eventPath && fs.existsSync(eventPath)) {
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
    repoPrivate = eventData?.repository?.private;
  }

  const upstream = 'google-github-actions/deploy-cloudrun';
  const action = process.env.GITHUB_ACTION_REPOSITORY;
  const docsUrl = 'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions';

  core.info('');
  core.info('\u001b[1;36mStepSecurity Maintained Action\u001b[0m');
  core.info(`Secure drop-in replacement for ${upstream}`);
  if (repoPrivate === false) core.info('\u001b[32m\u2713 Free for public repositories\u001b[0m');
  core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`);
  core.info('');

  if (repoPrivate === false) return;

  const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';
  const body: Record<string, string> = { action: action || '' };
  if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl;
  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
      body,
      { timeout: 3000 },
    );
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 403) {
      core.error(
        `\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m`,
      );
      core.error(`\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`);
      process.exit(1);
    }
    core.info('Timeout or API not reachable. Continuing to next step.');
  }
}

/**
 * Executes the main action. It includes the main business logic and is the
 * primary entry point. It is documented inline.
 */
export async function run(): Promise<void> {
  await validateSubscription();

  // Register metrics
  process.env.CLOUDSDK_CORE_DISABLE_PROMPTS = '1';
  process.env.CLOUDSDK_METRICS_ENVIRONMENT = 'github-actions-deploy-cloudrun';
  process.env.CLOUDSDK_METRICS_ENVIRONMENT_VERSION = appVersion;
  process.env.GOOGLE_APIS_USER_AGENT = `google-github-actions:google-github-deploy-cloudrun/${appVersion}`;

  // Warn if pinned to HEAD
  if (isPinnedToHead()) {
    logWarning(pinnedToHeadWarning('v1'));
  }

  try {
    // Get action inputs
    const image = getInput('image'); // Image ie us-docker.pkg.dev/...
    let service = getInput('service'); // Service name
    const job = getInput('job'); // Job name
    const metadata = getInput('metadata'); // YAML file
    const projectId = getInput('project_id');
    const gcloudVersion = await computeGcloudVersion(getInput('gcloud_version'));
    const gcloudComponent = presence(getInput('gcloud_component')); // Cloud SDK component version
    const envVars = getInput('env_vars'); // String of env vars KEY=VALUE,...
    const envVarsUpdateStrategy = getInput('env_vars_update_strategy') || 'merge';
    const secrets = parseKVString(getInput('secrets')); // String of secrets KEY=VALUE,...
    const secretsUpdateStrategy = getInput('secrets_update_strategy') || 'merge';
    const region = parseCSV(getInput('region') || 'us-central1');
    const source = getInput('source'); // Source directory
    const suffix = getInput('suffix');
    const tag = getInput('tag');
    const timeout = getInput('timeout');
    const noTraffic = (getInput('no_traffic') || '').toLowerCase() === 'true';
    const wait = parseBoolean(getInput('wait'));
    const revTraffic = getInput('revision_traffic');
    const tagTraffic = getInput('tag_traffic');
    const labels = parseKVString(getInput('labels'));
    const skipDefaultLabels = parseBoolean(getInput('skip_default_labels'));
    const flags = getInput('flags');
    const updateTrafficFlags = getInput('update_traffic_flags');

    let deployCmd: string[] = [];

    // Throw errors if inputs aren't valid
    if (revTraffic && tagTraffic) {
      throw new Error('Only one of `revision_traffic` or `tag_traffic` inputs can be set.');
    }
    if ((revTraffic || tagTraffic) && !service) {
      throw new Error('No service name set.');
    }
    if (source && image) {
      throw new Error('Only one of `source` or `image` inputs can be set.');
    }
    if (service && job) {
      throw new Error('Only one of `service` or `job` inputs can be set.');
    }

    // Validate gcloud component input
    if (gcloudComponent && gcloudComponent !== 'alpha' && gcloudComponent !== 'beta') {
      throw new Error(`invalid input received for gcloud_component: ${gcloudComponent}`);
    }

    // Find base command
    if (metadata) {
      const contents = await readFile(metadata, 'utf8');
      const parsed = parseYAML(contents);

      // Extract service name from metadata template
      const name = parsed?.metadata?.name;
      if (!name) {
        throw new Error(`${metadata} is missing 'metadata.name'`);
      }
      if (service && service != name) {
        throw new Error(
          `service name in ${metadata} ("${name}") does not match GitHub ` +
            `Actions service input ("${service}")`,
        );
      }
      service = name;

      const kind = parsed?.kind;
      if (kind === 'Service') {
        deployCmd = ['run', 'services', 'replace', metadata];
      } else if (kind === 'Job') {
        deployCmd = ['run', 'jobs', 'replace', metadata];
      } else {
        throw new Error(`Unkown metadata type "${kind}", expected "Job" or "Service"`);
      }
    } else if (job) {
      logWarning(
        `Support for Cloud Run jobs in this GitHub Action is in beta and is ` +
          `not covered by the semver backwards compatibility guarantee.`,
      );

      deployCmd = ['run', 'jobs', 'deploy', job];

      if (image) {
        deployCmd.push('--image', image);
      } else if (source) {
        deployCmd.push('--source', source);
      }

      // Set optional flags from inputs
      setEnvVarsFlags(deployCmd, envVars, envVarsUpdateStrategy);
      setSecretsFlags(deployCmd, secrets, secretsUpdateStrategy);

      if (wait) {
        deployCmd.push('--wait');
      }

      // There is no --update-secrets flag on jobs, but there will be in the
      // future. At that point, we can remove this.
      const idx = deployCmd.indexOf('--update-secrets');
      if (idx >= 0) {
        logWarning(
          `Cloud Run does not allow updating secrets on jobs, ignoring ` +
            `"secrets_update_strategy" value of "merge"`,
        );
        deployCmd[idx] = '--set-secrets';
      }

      // Compile the labels
      const defLabels = skipDefaultLabels ? {} : defaultLabels();
      const compiledLabels = Object.assign({}, defLabels, labels);
      if (compiledLabels && Object.keys(compiledLabels).length > 0) {
        deployCmd.push('--labels', joinKVStringForGCloud(compiledLabels));
      }
    } else {
      deployCmd = ['run', 'deploy', service];

      if (image) {
        deployCmd.push('--image', image);
      } else if (source) {
        deployCmd.push('--source', source);
      }

      // Set optional flags from inputs
      setEnvVarsFlags(deployCmd, envVars, envVarsUpdateStrategy);
      setSecretsFlags(deployCmd, secrets, secretsUpdateStrategy);

      if (tag) {
        deployCmd.push('--tag', tag);
      }
      if (suffix) deployCmd.push('--revision-suffix', suffix);
      if (noTraffic) deployCmd.push('--no-traffic');
      if (timeout) deployCmd.push('--timeout', timeout);

      // Compile the labels
      const defLabels = skipDefaultLabels ? {} : defaultLabels();
      const compiledLabels = Object.assign({}, defLabels, labels);
      if (compiledLabels && Object.keys(compiledLabels).length > 0) {
        deployCmd.push('--update-labels', joinKVStringForGCloud(compiledLabels));
      }
    }

    // Traffic flags
    let updateTrafficCmd = ['run', 'services', 'update-traffic', service];
    if (revTraffic) updateTrafficCmd.push('--to-revisions', revTraffic);
    if (tagTraffic) updateTrafficCmd.push('--to-tags', tagTraffic);

    // Push common flags
    deployCmd.push('--format', 'json');
    updateTrafficCmd.push('--format', 'json');

    if (region?.length > 0) {
      const regions = region
        .flat()
        .filter((e) => e !== undefined && e !== null && e !== '')
        .join(',');
      deployCmd.push('--region', regions);
      updateTrafficCmd.push('--region', regions);
    }
    if (projectId) {
      deployCmd.push('--project', projectId);
      updateTrafficCmd.push('--project', projectId);
    }

    // Add optional deploy flags
    if (flags) {
      const flagList = parseFlags(flags);
      if (flagList) {
        deployCmd = deployCmd.concat(flagList);
      }
    }

    // Add optional update-traffic flags
    if (updateTrafficFlags) {
      const flagList = parseFlags(updateTrafficFlags);
      if (flagList) {
        updateTrafficCmd = updateTrafficCmd.concat(flagList);
      }
    }

    // Install gcloud if not already installed.
    if (!isGcloudInstalled(gcloudVersion)) {
      await installGcloudSDK(gcloudVersion);
    } else {
      const toolPath = toolCache.find('gcloud', gcloudVersion);
      addPath(path.join(toolPath, 'bin'));
    }

    // Install gcloud component if needed and prepend the command
    if (gcloudComponent) {
      await installGcloudComponent(gcloudComponent);
      deployCmd.unshift(gcloudComponent);
      updateTrafficCmd.unshift(gcloudComponent);
    }

    // Authenticate - this comes from google-github-actions/auth.
    const credFile = process.env.GOOGLE_GHA_CREDS_PATH;
    if (credFile) {
      await authenticateGcloudSDK(credFile);
      logInfo('Successfully authenticated');
    } else {
      logWarning('No authentication found, authenticate with `google-github-actions/auth`.');
    }

    const toolCommand = getToolCommand();
    const options = { silent: !isDebug, ignoreReturnCode: true };
    const commandString = `${toolCommand} ${deployCmd.join(' ')}`;
    logInfo(`Running: ${commandString}`);
    logDebug(
      JSON.stringify({ toolCommand: toolCommand, args: deployCmd, options: options }, null, '  '),
    );

    // Run deploy command
    const deployCmdExec = await getExecOutput(toolCommand, deployCmd, options);
    if (deployCmdExec.exitCode !== 0) {
      const errMsg =
        deployCmdExec.stderr ||
        `command exited ${deployCmdExec.exitCode}, but stderr had no output`;
      throw new Error(`failed to deploy: ${errMsg}, full command:\n\t${commandString}`);
    }
    setActionOutputs(parseDeployResponse(deployCmdExec.stdout, { tag: tag }));

    // Run revision/tag command
    if (revTraffic || tagTraffic) {
      const updateTrafficExec = await getExecOutput(toolCommand, updateTrafficCmd, options);
      if (updateTrafficExec.exitCode !== 0) {
        const errMsg =
          updateTrafficExec.stderr ||
          `command exited ${updateTrafficExec.exitCode}, but stderr had no output`;
        throw new Error(`failed to update traffic: ${errMsg}, full command:\n\t${commandString}`);
      }
      setActionOutputs(parseUpdateTrafficResponse(updateTrafficExec.stdout));
    }
  } catch (err) {
    const msg = errorMessage(err);
    setFailed(`google-github-actions/google-github-deploy-cloudrun failed with: ${msg}`);
  }
}

// Map output response to GitHub Action outputs
export function setActionOutputs(outputs: DeployCloudRunOutputs): void {
  Object.keys(outputs).forEach((key: string) => {
    setOutput(key, outputs[key as keyof DeployCloudRunOutputs]);
  });
}

/**
 * defaultLabels returns the default labels to apply to the Cloud Run service.
 *
 * @return KVPair
 */
function defaultLabels(): KVPair {
  const rawValues: Record<string, string | undefined> = {
    'managed-by': 'github-actions',
    'commit-sha': process.env.GITHUB_SHA,
  };

  const labels: KVPair = {};
  for (const key in rawValues) {
    const value = rawValues[key];
    if (value) {
      // Labels can only be lowercase
      labels[key] = value.toLowerCase();
    }
  }

  return labels;
}

/**
 * computeGcloudVersion computes the appropriate gcloud version for the given
 * string.
 */
async function computeGcloudVersion(str: string): Promise<string> {
  str = (str || '').trim();
  if (str === '' || str === 'latest') {
    return await getLatestGcloudSDKVersion();
  }
  return str;
}

function setEnvVarsFlags(cmd: string[], envVars: string, strategy: string) {
  const compiledEnvVars = parseKVString(envVars);
  if (compiledEnvVars && Object.keys(compiledEnvVars).length > 0) {
    let flag = '';
    if (strategy === 'overwrite') {
      flag = '--set-env-vars';
    } else if (strategy === 'merge') {
      flag = '--update-env-vars';
    } else {
      throw new Error(
        `Invalid "env_vars_update_strategy" value "${strategy}", valid values ` +
          `are "overwrite" and "merge".`,
      );
    }
    cmd.push(flag, joinKVStringForGCloud(compiledEnvVars));
  }
}

function setSecretsFlags(cmd: string[], secrets: KVPair | undefined, strategy: string) {
  if (secrets && Object.keys(secrets).length > 0) {
    let flag = '';
    if (strategy === 'overwrite') {
      flag = '--set-secrets';
    } else if (strategy === 'merge') {
      flag = '--update-secrets';
    } else {
      throw new Error(
        `Invalid "secrets_update_strategy" value "${strategy}", valid values ` +
          `are "overwrite" and "merge".`,
      );
    }
    cmd.push(flag, joinKVStringForGCloud(secrets));
  }
}

/**
 * execute the main function when this module is required directly.
 */
if (require.main === module) {
  run();
}
