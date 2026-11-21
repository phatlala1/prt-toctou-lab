# R83 — CLOSED: SHIPPING PARSER DIFFERENTIAL NEGATIVE

## Goal

Compare the Azure Pipelines task-lib external-output sanitizer with the actual logging-command parser and registered commands from a supported shipping agent. A positive required a filtered line to be parsed as a registered command that was blocked, or not allowlisted, by the sanitizer mode.

## Pinned product identity

- Azure Pipelines task-lib version `5.283.3`
- task-lib commit `43673c958dc5fb40b898c5c7b5b7b5bf0ebd14bd`
- Azure Pipelines Agent release `v5.282.0`
- Agent source commit `2d408e314fdb7aed11ad36871d5c08b8c52c38b9`
- Linux x64 agent package SHA-256 `d7a8f9cc0241dbd2d1b26b7ee225ca518fd07e62176aa04668ef1a90a9e41188`

The harness loaded the released `Microsoft.VisualStudio.Services.Agent.dll` and `Agent.Worker.dll`, invoked the real public `Command.TryParse` method, and enumerated registered worker commands from the shipping extension classes.

## Corpus

- Targeted inputs: `709,996`
- Deterministic random inputs: `250,000`
- Sanitizer modes: block-all and default allowlist
- Total sanitizer evaluations: `1,919,992`
- Residual unique lines sent to the agent parser: `34,140`
- Logical lines parsed by the harness: `42,652`

The corpus covered case changes, extra and empty dot segments, properties, malformed terminators, CR/LF/NUL/NBSP/BOM/zero-width characters, Unicode case-folding candidates, nested and multiple markers, headers up to 512 characters, and deterministic random mutations.

## Result

- Parsed command lines: `25,628`
- Parsed registered commands: `24,284`
- Parsed allowlisted commands: `24,284`
- Parsed unknown commands: `1,344`
- Security bypasses: `0`
- Status: `RUNTIME_NEGATIVE_CLOSED`

The unknown commands used Unicode spellings such as `tasK.debug`. JavaScript lowercasing treated these as allowlisted-looking strings, but the shipping .NET agent did not resolve them to a registered command. They therefore produced no privileged effect.

## Evidence

- GitHub Actions run: `44937576213`
- Job: `136947475693`
- Artifact: `14720880080`
- Artifact ZIP SHA-256: `237fdb65c2ddc8dcb633ff7a4952a58f29c6c6a5f4c671d807b5b19b3cb62819`

## Decision

`DO_NOT_SUBMIT`

No sanitizer/parser mismatch reached a registered shipping-agent command. No MSRC report, final submission ZIP, or portal submission was created. Automatic workflow execution was disabled.
