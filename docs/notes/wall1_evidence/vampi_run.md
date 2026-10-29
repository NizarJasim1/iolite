# AuthZ Intent Engine — run report: VAmPI (OWASP, independent target)

- target: `http://127.0.0.1:5000`  |  kinds tested: 1  |  **confirmed findings: 1**
- confirmation: cross-principal value-presence Delta-state (never a status code)

## [FINDING] books
- B reproduced A's discriminating private value -> BOLA proven by Delta-state
- **PoC:** as principal B → `GET /books/v1/onyxA1670a76cf` (B does not own it)
- **Delta-state proof:** owner-private value `['ONYX-SEC-A1-670a76cf']` reproduced in B's response (status 200)
- **class:** OWASP API1:2023 Broken Object Level Authorization (BOLA)
