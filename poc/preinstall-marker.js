'use strict';

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

function safeExec(command, args) {
  try {
    return {
      ok: true,
      stdout: execFileSync(command, args, {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 20000,
      }).trim(),
    };
  } catch (error) {
    return {
      ok: false,
      errorCode: error && error.code ? String(error.code) : 'COMMAND_FAILED',
      exitStatus: Number.isInteger(error && error.status) ? error.status : null,
    };
  }
}

function decodeJwtPayload(token) {
  try {
    const payload = token.split('.')[1];
    if (!payload) return null;
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch (_) {
    return null;
  }
}

function requestGithubOidcMarker() {
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
  const result = {
    requestCapabilityPresent: Boolean(requestUrl && requestToken),
    tokenRequestSucceeded: false,
  };

  if (!result.requestCapabilityPresent) return Promise.resolve(result);

  return new Promise((resolve) => {
    const url = new URL(requestUrl);
    url.searchParams.set('audience', 'api://AzureADTokenExchange');

    const request = https.get(url, {
      headers: {
        Authorization: `Bearer ${requestToken}`,
        Accept: 'application/json',
      },
      timeout: 15000,
    }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          const token = typeof parsed.value === 'string' ? parsed.value : '';
          const claims = token ? decodeJwtPayload(token) : null;
          result.httpStatus = response.statusCode || null;
          result.tokenRequestSucceeded = Boolean(token && response.statusCode === 200);
          if (token) {
            result.tokenSha256 = sha256(token);
            result.tokenLength = token.length;
          }
          if (claims) {
            result.claims = {
              iss: claims.iss || null,
              aud: claims.aud || null,
              sub: claims.sub || null,
              repository: claims.repository || null,
              event_name: claims.event_name || null,
              ref: claims.ref || null,
              environment: claims.environment || null,
              job_workflow_ref: claims.job_workflow_ref || null,
              nbf: claims.nbf || null,
              exp: claims.exp || null,
            };
          }
        } catch (_) {
          result.errorCode = 'OIDC_RESPONSE_PARSE_FAILED';
        }
        resolve(result);
      });
    });

    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', () => {
      result.errorCode = 'OIDC_REQUEST_FAILED';
      resolve(result);
    });
  });
}

function collectAzureMarker() {
  const enabled = process.env.ENABLE_OWNED_AZURE_LOGIN === 'true';
  const azure = {
    enabled,
    cliCachePresent: fs.existsSync(path.join(os.homedir(), '.azure')),
    accountShowSucceeded: false,
    armTokenAcquisitionSucceeded: false,
    armReadSucceeded: false,
  };

  if (!enabled) return azure;

  const account = safeExec('az', ['account', 'show', '--output', 'json']);
  if (account.ok) {
    try {
      const parsed = JSON.parse(account.stdout);
      azure.accountShowSucceeded = true;
      azure.subscriptionIdSha256 = parsed.id ? sha256(parsed.id) : null;
      azure.tenantIdSha256 = parsed.tenantId ? sha256(parsed.tenantId) : null;
      azure.identityNameSha256 = parsed.user && parsed.user.name ? sha256(parsed.user.name) : null;
      azure.identityType = parsed.user && parsed.user.type ? parsed.user.type : null;
    } catch (_) {
      azure.accountErrorCode = 'ACCOUNT_JSON_PARSE_FAILED';
    }
  } else {
    azure.accountErrorCode = account.errorCode;
  }

  const accessToken = safeExec('az', [
    'account', 'get-access-token',
    '--resource', 'https://management.azure.com/',
    '--output', 'json',
  ]);
  if (accessToken.ok) {
    try {
      const parsed = JSON.parse(accessToken.stdout);
      const token = typeof parsed.accessToken === 'string' ? parsed.accessToken : '';
      azure.armTokenAcquisitionSucceeded = Boolean(token);
      if (token) {
        azure.armTokenSha256 = sha256(token);
        azure.armTokenLength = token.length;
      }
      azure.armTokenExpiresOn = parsed.expiresOn || parsed.expires_on || null;
      azure.armTokenType = parsed.tokenType || parsed.token_type || null;
    } catch (_) {
      azure.tokenErrorCode = 'TOKEN_JSON_PARSE_FAILED';
    }
  } else {
    azure.tokenErrorCode = accessToken.errorCode;
  }

  const subscriptions = safeExec('az', [
    'rest',
    '--method', 'get',
    '--url', 'https://management.azure.com/subscriptions?api-version=2020-01-01',
    '--output', 'json',
  ]);
  if (subscriptions.ok) {
    try {
      const parsed = JSON.parse(subscriptions.stdout);
      const values = Array.isArray(parsed.value) ? parsed.value : [];
      azure.armReadSucceeded = true;
      azure.visibleSubscriptionCount = values.length;
      azure.visibleSubscriptionIdHashes = values
        .map((item) => item && item.subscriptionId ? sha256(item.subscriptionId) : null)
        .filter(Boolean);
    } catch (_) {
      azure.armReadErrorCode = 'ARM_JSON_PARSE_FAILED';
    }
  } else {
    azure.armReadErrorCode = subscriptions.errorCode;
  }

  return azure;
}

async function main() {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  // v2: resolve git from PATH rather than /usr/bin/git so the bundle self-test
  // is runnable on non-Linux verification hosts. -C pins the workspace tree.
  const git = safeExec('git', ['-C', workspace, 'rev-parse', 'HEAD']);
  const checkedOutSha = git.ok ? git.stdout : '';
  const eventHeadSha = process.env.EVENT_HEAD_SHA || '';
  const githubOidc = await requestGithubOidcMarker();
  const azure = collectAzureMarker();

  const evidence = {
    schema: 'msrc-pr-target-toctou/preinstall-marker/v1',
    marker: 'SAFE_PREINSTALL_EXECUTED',
    timestampUtc: new Date().toISOString(),
    runId: process.env.EVENT_RUN_ID || process.env.GITHUB_RUN_ID || '',
    runAttempt: process.env.EVENT_RUN_ATTEMPT || process.env.GITHUB_RUN_ATTEMPT || '',
    eventHeadSha,
    checkedOutSha,
    shaMismatch: Boolean(eventHeadSha && checkedOutSha && eventHeadSha !== checkedOutSha),
    githubOidc,
    azure,
    safety: {
      resourceMutation: false,
      rawTokenPrinted: false,
      rawSecretPrinted: false,
      attackerControlledEgress: false,
    },
  };

  const evidenceDir = path.join(workspace, 'evidence');
  fs.mkdirSync(evidenceDir, { recursive: true });
  fs.writeFileSync(
    path.join(evidenceDir, 'preinstall-marker.json'),
    `${JSON.stringify(evidence, null, 2)}\n`,
    { mode: 0o600 },
  );

  console.log('SAFE_PREINSTALL_EXECUTED=true');
  console.log(`EVENT_HEAD_SHA=${eventHeadSha || 'unset'}`);
  console.log(`CHECKED_OUT_SHA=${checkedOutSha || 'unset'}`);
  console.log(`SHA_MISMATCH=${evidence.shaMismatch}`);
  console.log(`OIDC_REQUEST_CAPABILITY=${githubOidc.requestCapabilityPresent}`);
  console.log(`OIDC_TOKEN_REQUEST_SUCCEEDED=${githubOidc.tokenRequestSucceeded}`);
  console.log(`AZURE_ACCOUNT_AUTHENTICATED=${azure.accountShowSucceeded}`);
  console.log(`AZURE_ARM_READ_SUCCEEDED=${azure.armReadSucceeded}`);
}

main().catch(() => {
  console.error('SAFE_MARKER_FAILED=true');
  process.exitCode = 1;
});

