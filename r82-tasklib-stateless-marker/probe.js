'use strict';

const fs = require('fs');
const path = require('path');
const stream = require('stream');

if (process.argv.length !== 4) {
  console.error('usage: node probe.js <task-lib-compiled-directory> <result.json>');
  process.exit(2);
}

const compiledDirectory = path.resolve(process.argv[2]);
const resultPath = path.resolve(process.argv[3]);
const taskLib = require(path.join(compiledDirectory, 'task.js'));
const externalOutput = require(path.join(compiledDirectory, 'externaloutput.js'));
const packagePathCandidates = [
  path.join(compiledDirectory, 'package.json'),
  path.join(compiledDirectory, '..', 'package.json'),
];
const packagePath = packagePathCandidates.find(candidate => fs.existsSync(candidate));
if (!packagePath) {
  throw new Error(`task-lib package.json not found near ${compiledDirectory}`);
}

function capture(action) {
  const sink = new stream.PassThrough();
  const chunks = [];
  sink.on('data', chunk => chunks.push(Buffer.from(chunk)));
  action(sink);
  sink.end();
  return Buffer.concat(chunks).toString('utf8');
}

const options = destination => ({
  source: 'repository',
  vsoCommandMode: 'blockAndTelemetry',
  destination,
});

const splitAcrossIndependentCalls = capture(sink => {
  taskLib.writeExternalOutput('##v', options(sink));
  taskLib.writeExternalOutput('so[task.setvariable variable=R82_SYNTHETIC]true\n', options(sink));
});

const completeSingleCall = capture(sink => {
  taskLib.writeExternalOutput(
    '##vso[task.setvariable variable=R82_SYNTHETIC]true\n',
    options(sink));
});

const statefulWriter = capture(sink => {
  const writer = externalOutput.createFilteredWriter(options(sink), sink);
  writer.write('##v');
  writer.write('so[task.setvariable variable=R82_SYNTHETIC]true\n');
  writer.end();
});

const executableMarker = '##vso[task.setvariable variable=R82_SYNTHETIC]true';
const neutralizedMarker = '##_vso[task.setvariable variable=R82_SYNTHETIC]true';

const result = {
  schema: 'r82-tasklib-stateless-marker-differential/v1',
  taskLibVersion: require(packagePath).version,
  compiledDirectory,
  splitAcrossIndependentCalls,
  completeSingleCall,
  statefulWriter,
  gates: {
    splitCallsReconstructExecutableMarker: splitAcrossIndependentCalls.includes(executableMarker),
    singleCallIsNeutralized: completeSingleCall.includes(neutralizedMarker)
      && !completeSingleCall.includes(executableMarker),
    statefulWriterIsNeutralized: statefulWriter.includes(neutralizedMarker)
      && !statefulWriter.includes(executableMarker),
  },
};
result.coreDifferentialObserved = Object.values(result.gates).every(Boolean);
result.securityVerdict = result.coreDifferentialObserved
  ? 'CORE_API_DIFFERENTIAL_ONLY_REAL_TASK_CALLSITE_REQUIRED'
  : 'RUNTIME_NEGATIVE_OR_INVALID';

fs.mkdirSync(path.dirname(resultPath), { recursive: true });
fs.writeFileSync(resultPath, JSON.stringify(result, null, 2) + '\n', 'utf8');
console.log(JSON.stringify(result, null, 2));
process.exit(result.coreDifferentialObserved ? 10 : 0);
