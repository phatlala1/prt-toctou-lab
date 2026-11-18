# R60 — REAL RUNTIME POSITIVE / HOLD / DO NOT SUBMIT YET

Candidate: `.NET MapOpenAIResponses` persists and exposes a response and its input items even when the caller explicitly sends `"store": false`.

Published packages tested:

- `Microsoft.Agents.AI.Hosting` `1.28.0-preview.261106.1`
- `Microsoft.Agents.AI.Hosting.OpenAI` `1.28.0-alpha.261106.1`
- `Microsoft.Extensions.AI` `10.11.0`

Hosted positive: run `44279452994`, job `134715968189`, commit `3f4233d5b69951b83800f8599e18e6343d27b3c2`.

Observed behavior:

- `POST /v1/responses` with `"store": false` returned `200` and a response object that still reported `"store": false`.
- `GET /v1/responses/{response_id}` returned `200` and the completed response.
- `GET /v1/responses/{response_id}/input_items` returned `200` and the full synthetic private input `R60_PRIVATE_INPUT_STORE_FALSE`.
- Matched `"store": true` response and input-items controls returned `200`.
- No external model, API key, network service, privileged credential, or destructive action was used.

Evidence artifact: `14415578217`; uploaded ZIP SHA-256 `221856332c5fbaf646c43213b3cd7ffbbf8be0c41a50b4956ff22a35f3f43f8b`.

Current disposition:

- Product behavior is runtime-proven and conflicts with the explicit `store=false` request.
- Current evidence proves unintended retention/retrieval of the caller's own data, but not an independent lower-trust actor reading or modifying protected data.
- No distinct Important/Critical MSRC boundary crossing is established.
- Do not submit as a new case and do not create a final submission ZIP unless a distinct cross-user/cross-tenant or protected availability impact is proved without reusing the frozen hosted-state ownership root.
