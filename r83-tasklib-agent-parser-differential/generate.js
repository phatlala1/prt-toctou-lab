'use strict';

const fs = require('fs');
const path = require('path');

if (process.argv.length !== 6) {
  console.error('usage: node generate.js <compiled-task-lib-dir> <cases.jsonl> <stats.json> <random-count>');
  process.exit(2);
}

const compiledDir = path.resolve(process.argv[2]);
const casesPath = path.resolve(process.argv[3]);
const statsPath = path.resolve(process.argv[4]);
const randomCount = Number(process.argv[5]);
if (!Number.isSafeInteger(randomCount) || randomCount < 0) {
  throw new Error(`invalid random count: ${process.argv[5]}`);
}

const externalOutput = require(path.join(compiledDir, 'externaloutput.js'));
fs.mkdirSync(path.dirname(casesPath), { recursive: true });
const output = fs.createWriteStream(casesPath, { encoding: 'utf8' });
const seenResidual = new Set();

const knownCommands = [
  'task.debug',
  'task.setprogress',
  'task.setvariable',
  'task.prependpath',
  'task.setsecret',
  'task.setendpoint',
  'task.complete',
  'task.logissue',
  'task.uploadfile',
  'task.addattachment',
  'artifact.associate',
  'build.updatebuildnumber',
  'release.updatereleasename',
  'telemetry.publish',
];
const prefixes = ['', 'x', 'prefix:', '\uFEFF', '\u200B'];
const suffixes = ['', 'data', '\n', 'tail##vso[task.setvariable variable=R83]x'];
const propertyForms = [
  '',
  ' variable=R83',
  ' variable=R83;isOutput=true;',
  '\tvariable=R83',
  '\u00a0variable=R83',
];
const terminators = [']', ' ]', '\t]', '\u00a0]', '\u0000]', '\r]', '\n]'];
const markerForms = ['##vso[', 'x##vso[', '##vso[##vso['];

let id = 0;
const stats = {
  schema: 'r83-tasklib-agent-parser-corpus/v1',
  taskLibVersion: null,
  targetedInputs: 0,
  randomInputs: randomCount,
  evaluatedByMode: { block: 0, allowDefault: 0 },
  residualByMode: { block: 0, allowDefault: 0 },
  uniqueResidualByMode: { block: 0, allowDefault: 0 },
  emittedCases: 0,
  unicodeSubstitutions: {},
};

const packageCandidates = [
  path.join(compiledDir, 'package.json'),
  path.join(compiledDir, '..', 'package.json'),
];
const packagePath = packageCandidates.find(p => fs.existsSync(p));
stats.taskLibVersion = packagePath ? require(packagePath).version : 'unknown';

function toB64(value) {
  return Buffer.from(value, 'utf8').toString('base64');
}

function filter(input, mode) {
  const options = mode === 'block'
    ? { source: 'remote', vsoCommandMode: 'blockOnly', enableVsoCommands: false }
    : { source: 'remote', vsoCommandMode: 'blockOnly', enableVsoCommands: true };
  return externalOutput.filterExternalOutput(input, options).toString('utf8');
}

function evaluate(input, origin) {
  for (const mode of ['block', 'allowDefault']) {
    stats.evaluatedByMode[mode]++;
    const filtered = filter(input, mode);
    if (!filtered.includes('##vso[')) continue;

    stats.residualByMode[mode]++;
    const key = `${mode}\u0000${filtered}`;
    if (seenResidual.has(key)) continue;
    seenResidual.add(key);
    stats.uniqueResidualByMode[mode]++;

    output.write(JSON.stringify({
      id: ++id,
      mode,
      origin,
      originalB64: toB64(input),
      filteredB64: toB64(filtered),
    }) + '\n');
    stats.emittedCases++;
  }
}

function dotVariants(command) {
  const [area, event] = command.split('.');
  return [
    command,
    command.toUpperCase(),
    `${area}..${event}`,
    `.${area}.${event}.`,
    `${area}...${event}`,
    `${area}.${event}.extra`,
    area,
  ];
}

function buildLowercaseSubstitutions() {
  const targets = new Set('abcdefghijklmnopqrstuvwxyz');
  const mapping = Object.fromEntries([...targets].map(c => [c, new Set([c, c.toUpperCase()])]));
  for (let cp = 0; cp <= 0xffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const ch = String.fromCodePoint(cp);
    const lowered = ch.toLowerCase();
    if (lowered.length === 1 && targets.has(lowered)) mapping[lowered].add(ch);
  }
  return Object.fromEntries(
    Object.entries(mapping).map(([key, values]) => [key, [...values].slice(0, 64)]));
}

const substitutions = buildLowercaseSubstitutions();
stats.unicodeSubstitutions = Object.fromEntries(
  Object.entries(substitutions).map(([key, values]) => [
    key,
    values.map(value => `U+${value.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`),
  ]));

function unicodeVariants(command) {
  const variants = new Set([command]);
  for (let i = 0; i < command.length; i++) {
    const choices = substitutions[command[i].toLowerCase()] || [];
    for (const replacement of choices) {
      if (replacement !== command[i]) {
        variants.add(command.slice(0, i) + replacement + command.slice(i + 1));
      }
    }
  }
  // One deterministic two-position substitution per command is enough to expose
  // cross-runtime case-folding composition without a combinatorial explosion.
  const positions = [];
  for (let i = 0; i < command.length; i++) {
    const alternate = (substitutions[command[i].toLowerCase()] || []).find(v => v !== command[i]);
    if (alternate) positions.push([i, alternate]);
  }
  if (positions.length >= 2) {
    const chars = [...command];
    chars[positions[0][0]] = positions[0][1];
    chars[positions[1][0]] = positions[1][1];
    variants.add(chars.join(''));
  }
  return [...variants];
}

for (const command of knownCommands) {
  const commands = new Set([...dotVariants(command), ...unicodeVariants(command)]);
  for (const candidate of commands) {
    for (const marker of markerForms) {
      for (const property of propertyForms) {
        for (const terminator of terminators) {
          for (const prefix of prefixes) {
            for (const suffix of suffixes) {
              evaluate(`${prefix}${marker}${candidate}${property}${terminator}${suffix}`, `target:${command}`);
              stats.targetedInputs++;
            }
          }
        }
      }
    }
  }
}

for (const length of [0, 1, 2, 6, 7, 8, 31, 63, 127, 255, 256, 257, 300, 512]) {
  for (const char of ['a', '.', ' ', ']', '\u0000', '\u00a0', '\u212A']) {
    evaluate(`##vso[${char.repeat(length)}]payload`, `long:${length}:${char.codePointAt(0)}`);
    evaluate(`prefix##vso[task.debug]x##vso[${char.repeat(length)}]payload`, `multi:${length}:${char.codePointAt(0)}`);
    stats.targetedInputs += 2;
  }
}

let state = 0x83c0ffee >>> 0;
function random32() {
  state ^= state << 13;
  state ^= state >>> 17;
  state ^= state << 5;
  return state >>> 0;
}
const alphabet = [
  ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .;=]_[%#',
  '\t', '\r', '\n', '\u0000', '\u000b', '\u000c', '\u0085', '\u00a0', '\u200b', '\u2028', '\u2029', '\u212a', '\ufeff',
];
for (let n = 0; n < randomCount; n++) {
  const leftLength = random32() % 80;
  const rightLength = random32() % 320;
  let left = '';
  let right = '';
  for (let i = 0; i < leftLength; i++) left += alphabet[random32() % alphabet.length];
  for (let i = 0; i < rightLength; i++) right += alphabet[random32() % alphabet.length];
  evaluate(`${left}##vso[${right}`, `random:${n}`);
}

output.end(() => {
  fs.writeFileSync(statsPath, JSON.stringify(stats, null, 2) + '\n', 'utf8');
  console.log(JSON.stringify(stats, null, 2));
});
