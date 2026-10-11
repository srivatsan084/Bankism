# AI Firewall for Banking

The LLM is an untrusted parser; only deterministic code can authorize money movement.

## Status

Prototype. Tests: 43/43 passing.

## Architecture

Gate A: Pre-filter enforcing size limits, rate limits, character normalization, and pattern blocking.
Gate B: Semantic guardrails detecting payment card numbers and jailbreak patterns via keyword stubs.
Gate C: Intent extraction using regex stubs and validating actions against a versioned schema.
Gate D: Deterministic enforcement validating sessions, limits, and HMAC confirmation tokens.
Gate E: Output filter sanitizing responses to remove HTML and markdown image exfiltration.
/support: Read-only service permitting balance and statement actions.
/payments: Money movement service that executes transfers and fails closed.
/parsing: Untrusted text scanning service with no execution rights.

## Run

```bash
pip install -r requirements.txt
uvicorn app:app --reload
python -m pytest
```

## Example

```bash
curl -X POST http://localhost:8000/payments -H "Content-Type: application/json" -d '{"text": "Send 50 bucks to Sarah"}'
```

```bash
curl -X POST http://localhost:8000/payments -H "Content-Type: application/json" -d '{"text": "Send 50 bucks to Sarah", "token": "<confirmation_token>"}'
```

## Mocked components

Session, beneficiary list, ledger are mocked. Step-up auth and cooling-off are simplified (a "new" beneficiary is simply blocked). Confirmation is a second API call carrying the token, not an out-of-band screen. The token doubles as the idempotency key.

## Deployment

One codebase, one instance per service:
```bash
FIREWALL_SERVICES=support uvicorn app:app --port 8001
FIREWALL_SERVICES=payments uvicorn app:app --port 8002
FIREWALL_SERVICES=parsing uvicorn app:app --port 8003
```
For several replicas of a service, set the same FIREWALL_SECRET on all of them, set REDIS_URL so rate limits are shared, and put a load balancer in front.

Replicating /payments is NOT safe with the mocked ledger: each process has its own balance and its own idempotency set, so a replayed token could debit twice. Replicate /payments only after the ledger is a shared database with atomic transactions. /support (when it only reads) and /parsing are stateless enough to replicate.

If Redis is unreachable, the rate limiter falls back to per-process limits, so the effective limit becomes the limit times the number of replicas.

## Known limitations

Gates B and C are keyword/regex stubs and can be bypassed by paraphrase; security rests on Gate D. Rate limiting is in-memory and single-process. Amount parsing returns ambiguous when it finds more than one number. No Hindi/Hinglish number words yet. Verdict has two fields beyond the design doc: confirmation_token and data.
