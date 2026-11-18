# R61 — CLOSED: NEGATIVE VALIDATION

Candidate: OpenAI Conversations nested item routes might fail to bind `{item_id}` to `{conversation_id}` and the current caller isolation key.

Published packages tested:

- `Microsoft.Agents.AI.Hosting` `1.28.0-preview.261106.1`
- `Microsoft.Agents.AI.Hosting.AspNetCore` `1.28.0-preview.261106.1`
- `Microsoft.Agents.AI.Hosting.OpenAI` `1.28.0-alpha.261106.1`

Hosted run: `44280956332`, job `134721200039`, Ubuntu hosted runner, .NET SDK `11.0.100` / runtime `11.0.0`.

Results:

- Alice correct conversation/item GET: `200`.
- Bob correct conversation/item GET: `200`.
- Alice item requested under Alice's other conversation: GET `404`, DELETE `404`.
- Alice item requested by Bob under Alice's conversation: GET `404`.
- Alice item requested by Bob under Bob's own conversation: GET `404`, DELETE `404`.
- Alice correct GET after both unauthorized delete attempts: `200`; private marker remained intact.

Conclusion: the tested implementation binds conversation items to both the parent conversation and caller isolation partition. No confidentiality or integrity boundary crossing was observed. No MSRC report or final ZIP was created.

Evidence artifact: run artifact `14416479029`, SHA-256 `277704bbca163191c655f4dc2c0b213137827598b91b9b0763e547d8549af359`.
