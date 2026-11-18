import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { chromium, firefox, webkit, request } from 'playwright';

const victim = 'https://victim.test:5001';
const attacker = 'https://attacker.test:5002';
const evidenceDir = path.resolve('evidence');
fs.mkdirSync(evidenceDir, { recursive: true });

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function getJson(response) {
  if (!response.ok()) {
    throw new Error(`HTTP ${response.status()} ${response.statusText()}: ${await response.text()}`);
  }
  return response.json();
}

async function reset(context) {
  await getJson(await context.request.get(`${victim}/reset`));
}

async function state(context) {
  return getJson(await context.request.get(`${victim}/state`));
}

function summarizeCase(engine, testCase, snapshot, extra = {}) {
  const authenticatedRequests = snapshot.requests.filter((entry) => entry.authenticated);
  return {
    engine,
    id: testCase.id,
    actorClass: testCase.actorClass,
    description: testCase.description,
    mutationCount: snapshot.mutationCount,
    mutated: snapshot.mutationCount > 0,
    authenticatedRequestObserved: authenticatedRequests.length > 0,
    requests: snapshot.requests,
    mutations: snapshot.mutations,
    ...extra,
  };
}

const browserCases = [
  {
    id: 'form-auto',
    actorClass: 'remote-web-attacker',
    description: 'Cross-site top-level auto-submitted HTML form.',
    run: async (page) => page.goto(`${attacker}/attack/form-auto`, { waitUntil: 'domcontentloaded' }),
  },
  {
    id: 'form-click',
    actorClass: 'remote-web-attacker',
    description: 'Cross-site form submitted by a real user gesture.',
    run: async (page) => {
      await page.goto(`${attacker}/attack/form-click`, { waitUntil: 'domcontentloaded' });
      await page.click('#go');
    },
  },
  {
    id: 'sandbox-script',
    actorClass: 'remote-web-attacker',
    description: 'Opaque sandboxed iframe with scripts and forms enabled.',
    run: async (page) => page.goto(`${attacker}/attack/sandbox-script`, { waitUntil: 'domcontentloaded' }),
  },
  {
    id: 'sandbox-click',
    actorClass: 'remote-web-attacker',
    description: 'Opaque sandboxed iframe without scripts, submitted by a click.',
    run: async (page) => {
      await page.goto(`${attacker}/attack/sandbox-click`, { waitUntil: 'domcontentloaded' });
      const frame = page.frames().find((candidate) => candidate !== page.mainFrame());
      if (!frame) {
        throw new Error('sandbox iframe was not created');
      }
      await frame.click('#go');
    },
  },
  {
    id: 'data-iframe',
    actorClass: 'remote-web-attacker',
    description: 'Attacker embeds an opaque data: iframe that submits a form.',
    run: async (page) => page.goto(`${attacker}/attack/data-iframe`, { waitUntil: 'domcontentloaded' }),
  },
  {
    id: 'blob-top',
    actorClass: 'remote-web-attacker',
    description: 'Attacker navigates itself to a generated blob: document before form submission.',
    run: async (page) => page.goto(`${attacker}/attack/blob-top`, { waitUntil: 'domcontentloaded' }),
  },
  {
    id: 'popup-write',
    actorClass: 'remote-web-attacker',
    description: 'User gesture opens about:blank and writes an auto-submitting form.',
    run: async (page) => {
      await page.goto(`${attacker}/attack/popup-write`, { waitUntil: 'domcontentloaded' });
      const popupPromise = page.waitForEvent('popup');
      await page.click('#go');
      await popupPromise;
    },
  },
  {
    id: 'fetch-no-cors',
    actorClass: 'remote-web-attacker',
    description: 'Credentialed no-cors simple POST from attacker JavaScript.',
    run: async (page) => page.goto(`${attacker}/attack/fetch-no-cors`, { waitUntil: 'domcontentloaded' }),
  },
  {
    id: 'redirect307',
    actorClass: 'remote-web-attacker',
    description: 'Cross-site form POST redirected with HTTP 307 to the victim endpoint.',
    run: async (page) => page.goto(`${attacker}/attack/redirect307`, { waitUntil: 'domcontentloaded' }),
  },
  {
    id: 'data-top-direct',
    actorClass: 'opaque-navigation-control',
    description: 'Direct top-level data: navigation; not counted as a remote-web positive.',
    run: async (page) => {
      const html = `<!doctype html><form id="attack" method="post" action="${victim}/protected/form"><input name="marker" value="data-top-direct"></form><script>document.getElementById('attack').submit()</script>`;
      await page.goto(`data:text/html,${encodeURIComponent(html)}`, { waitUntil: 'domcontentloaded' });
    },
  },
];

const engines = [
  ['chromium', chromium],
  ['firefox', firefox],
  ['webkit', webkit],
];

const result = {
  schema: 'r64-dotnet11-csrf-browser-matrix/v1',
  testedAtUtc: new Date().toISOString(),
  target: 'stock ASP.NET Core .NET 11 automatic CSRF protection',
  controls: [],
  cases: [],
  engineErrors: [],
};

for (const [engineName, browserType] of engines) {
  let browser;
  try {
    browser = await browserType.launch({ headless: true });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const controller = await context.newPage();

    const loginResponse = await controller.goto(`${victim}/login`, { waitUntil: 'domcontentloaded' });
    if (!loginResponse || loginResponse.status() !== 200) {
      throw new Error(`login failed with ${loginResponse?.status()}`);
    }

    const cookies = await context.cookies(victim);
    const authCookie = cookies.find((cookie) => cookie.name === 'R64.Auth');
    if (!authCookie || authCookie.sameSite !== 'None' || !authCookie.secure) {
      throw new Error(`expected secure SameSite=None auth cookie, got ${JSON.stringify(cookies)}`);
    }

    // Positive control: a same-origin browser POST must reach and mutate the protected handler.
    await reset(context);
    const sameOriginStatus = await controller.evaluate(async (url) => {
      const response = await fetch(url, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'marker=same-origin-control',
      });
      return response.status;
    }, `${victim}/protected/form`);
    await delay(300);
    const sameOriginState = await state(context);
    result.controls.push({
      engine: engineName,
      id: 'same-origin-browser-post',
      status: sameOriginStatus,
      passed: sameOriginStatus === 200 && sameOriginState.mutationCount === 1,
      snapshot: sameOriginState,
    });

    // Negative control: an Origin-bearing synthetic request without Sec-Fetch-Site must fail Origin-vs-Host.
    await reset(context);
    const cookieHeader = cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ');
    const originFallbackClient = await request.newContext({
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: {
        Cookie: cookieHeader,
        Origin: attacker,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    const originFallbackResponse = await originFallbackClient.post(`${victim}/protected/form`, {
      data: 'marker=origin-fallback-control',
    });
    await originFallbackClient.dispose();
    const originFallbackState = await state(context);
    result.controls.push({
      engine: engineName,
      id: 'origin-fallback-control',
      status: originFallbackResponse.status(),
      passed: originFallbackState.mutationCount === 0,
      snapshot: originFallbackState,
    });

    // Reachability control: a non-browser client can forge Sec-Fetch-Site:none. This is intentionally
    // excluded from the vulnerability decision; it only confirms the server's documented accept branch.
    await reset(context);
    const forgedNoneClient = await request.newContext({
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: {
        Cookie: cookieHeader,
        Origin: attacker,
        'Sec-Fetch-Site': 'none',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    const forgedNoneResponse = await forgedNoneClient.post(`${victim}/protected/form`, {
      data: 'marker=forged-none-control',
    });
    await forgedNoneClient.dispose();
    const forgedNoneState = await state(context);
    result.controls.push({
      engine: engineName,
      id: 'synthetic-forged-none-control',
      status: forgedNoneResponse.status(),
      passed: forgedNoneState.mutationCount === 1,
      excludedFromSecurityVerdict: true,
      snapshot: forgedNoneState,
    });

    for (const testCase of browserCases) {
      await reset(context);
      const page = await context.newPage();
      let executionError = null;
      try {
        await testCase.run(page);
      } catch (error) {
        executionError = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      }
      await delay(1500);
      const snapshot = await state(context);
      result.cases.push(summarizeCase(engineName, testCase, snapshot, { executionError }));

      for (const candidate of context.pages()) {
        if (candidate !== controller) {
          await candidate.close().catch(() => {});
        }
      }
    }

    await context.close();
  } catch (error) {
    result.engineErrors.push({
      engine: engineName,
      error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    });
  } finally {
    await browser?.close().catch(() => {});
  }
}

const requiredControlIds = [
  'same-origin-browser-post',
  'origin-fallback-control',
  'synthetic-forged-none-control',
];
const controlMatrixComplete = engines.every(([engineName]) =>
  requiredControlIds.every((id) => result.controls.some((control) =>
    control.engine === engineName && control.id === id && control.passed)));
const remoteWebBypasses = result.cases.filter((entry) =>
  entry.actorClass === 'remote-web-attacker'
  && entry.mutated
  && entry.authenticatedRequestObserved);
const opaqueNavigationSignals = result.cases.filter((entry) =>
  entry.actorClass === 'opaque-navigation-control'
  && entry.mutated
  && entry.authenticatedRequestObserved);

result.verdict = {
  controlMatrixComplete,
  engineErrors: result.engineErrors.length,
  remoteWebBypassCount: remoteWebBypasses.length,
  opaqueNavigationSignalCount: opaqueNavigationSignals.length,
  status: !controlMatrixComplete || result.engineErrors.length > 0
    ? 'INVALID_RUNTIME'
    : remoteWebBypasses.length > 0
      ? 'RUNTIME_POSITIVE_REVIEW_REQUIRED'
      : 'RUNTIME_NEGATIVE_CLOSED',
  remoteWebBypasses: remoteWebBypasses.map((entry) => ({
    engine: entry.engine,
    id: entry.id,
    mutations: entry.mutations,
    requests: entry.requests,
  })),
  opaqueNavigationSignals: opaqueNavigationSignals.map((entry) => ({
    engine: entry.engine,
    id: entry.id,
    mutations: entry.mutations,
    requests: entry.requests,
  })),
};

fs.writeFileSync(
  path.join(evidenceDir, 'result.json'),
  `${JSON.stringify(result, null, 2)}\n`,
  'utf8',
);
fs.writeFileSync(
  path.join(evidenceDir, 'summary.txt'),
  [
    `status=${result.verdict.status}`,
    `controlMatrixComplete=${result.verdict.controlMatrixComplete}`,
    `engineErrors=${result.verdict.engineErrors}`,
    `remoteWebBypassCount=${result.verdict.remoteWebBypassCount}`,
    `opaqueNavigationSignalCount=${result.verdict.opaqueNavigationSignalCount}`,
  ].join('\n') + '\n',
  'utf8',
);

console.log(JSON.stringify(result.verdict, null, 2));
if (!controlMatrixComplete || result.engineErrors.length > 0) {
  process.exitCode = 2;
}
