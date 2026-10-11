"""Gate D: deterministic enforcement boundary. The only layer that can authorize execution."""

import hashlib
import hmac
import json
import os
import time

import mocks

ALLOWED_ACTIONS = {"balance", "statement", "transfer"}
TOKEN_TTL = 120
# Set the same FIREWALL_SECRET on every replica, or tokens issued by one will fail on another.
SECRET = os.environ["FIREWALL_SECRET"].encode() if os.environ.get("FIREWALL_SECRET") else os.urandom(32)

# MOCKED: step-up authentication and cooling-off timers are simplified in this prototype.


def _verdict(decision, risk, category, reason, params=None, token=None, executed=False, data=None) -> dict:
    return {
        "decision": decision,
        "risk_level": risk,
        "threat_category": category,
        "reason": reason,
        "params": params,
        "confirmation_token": token,
        "executed": executed,
        "data": data,
    }


def resolve_beneficiary(name: str, user_id: str) -> dict:
    if any(char.isdigit() for char in name):
        return {"status": "rejected"}
    n = name.strip().lower()
    matches = [
        beneficiary_id
        for beneficiary_id, beneficiary in mocks.get_beneficiaries(user_id).items()
        if n == beneficiary["name"].lower() or n in beneficiary["aliases"]
    ]
    if len(matches) == 0:
        return {"status": "none"}
    if len(matches) >= 2:
        return {"status": "multiple"}
    return {"status": "ok", "beneficiary_id": matches[0]}


def check_policy(amount: int, beneficiary_id: str, user_id: str) -> str | None:
    if amount > mocks.PER_TXN_LIMIT:
        return "per_txn_limit"
    if mocks.ledger.spent_today + amount > mocks.DAILY_LIMIT:
        return "daily_limit"
    if mocks.get_beneficiaries(user_id)[beneficiary_id]["status"] == "new":
        return "cooling_off"
    return None


def _params_hash(params: dict) -> str:
    return hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()


def issue_token(params: dict, now: float | None = None) -> str:
    if now is None:
        now = time.time()
    expiry = int(now) + TOKEN_TTL
    payload = f"{_params_hash(params)}.{expiry}"
    sig = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_token(token, params: dict, now: float | None = None) -> bool:
    try:
        if not isinstance(token, str):
            return False
        parts = token.split(".")
        if len(parts) != 3:
            return False
        params_hash, expiry, sig = parts
        payload = f"{params_hash}.{expiry}"
        expected = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        expiry_int = int(expiry)
        if now is None:
            now = time.time()
        if int(now) > expiry_int:
            return False
        if params_hash != _params_hash(params):
            return False
        return True
    except Exception:
        return False


def enforce(intent: dict, session: dict, token: str | None = None) -> dict:
    """Enforce deterministic payment policy."""
    if "user_id" not in session or "account_id" not in session:
        return _verdict("blocked", "high", "none", "no_session")
    action = intent.get("action")
    if action not in ALLOWED_ACTIONS:
        return _verdict("blocked", "high", "none", "action_not_allowed")
    if action == "balance":
        return _verdict(
            "approved",
            "low",
            "none",
            "read_only",
            executed=True,
            data={"balance": mocks.ledger.get_balance()},
        )
    if action == "statement":
        return _verdict(
            "approved",
            "low",
            "none",
            "read_only",
            executed=True,
            data={"transactions": list(mocks.ledger.transactions)},
        )
    amount = intent.get("amount")
    name = intent.get("beneficiary_name")
    if (
        not isinstance(amount, int)
        or isinstance(amount, bool)
        or amount <= 0
        or not isinstance(name, str)
        or not name.strip()
    ):
        return _verdict("needs_clarification", "medium", "ambiguous", "invalid_intent")
    r = resolve_beneficiary(name, session["user_id"])
    if r["status"] == "rejected":
        return _verdict("blocked", "high", "policy_override", "raw_account_in_name")
    if r["status"] == "none":
        return _verdict("blocked", "medium", "none", "beneficiary_not_found")
    if r["status"] == "multiple":
        return _verdict("needs_clarification", "medium", "ambiguous", "multiple_matches")
    reason = check_policy(amount, r["beneficiary_id"], session["user_id"])
    if reason is not None:
        return _verdict("blocked", "medium", "none", reason)
    params = {
        "action": "transfer",
        "user_id": session["user_id"],
        "account_id": session["account_id"],
        "beneficiary_id": r["beneficiary_id"],
        "amount": amount,
    }
    if token is None:
        return _verdict(
            "approved",
            "low",
            "none",
            "confirmation_required",
            params=params,
            token=issue_token(params),
        )
    if not verify_token(token, params):
        return _verdict("blocked", "high", "none", "invalid_or_expired_token")
    result = mocks.ledger.debit(amount, r["beneficiary_id"], token)
    if result["status"] == "ok":
        return _verdict(
            "approved",
            "low",
            "none",
            "executed",
            params=params,
            executed=True,
            data={"balance": result["balance"]},
        )
    if result["status"] == "duplicate":
        return _verdict("blocked", "medium", "none", "duplicate")
    if result["status"] == "insufficient_funds":
        return _verdict("blocked", "medium", "none", "insufficient_funds")
    return _verdict("blocked", "high", "none", "execution_failed")
