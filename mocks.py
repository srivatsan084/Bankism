"""Mocked session, beneficiaries, and ledger. These stand in for real banking systems."""

# MOCKED: none of this is a real banking system.

import threading

PER_TXN_LIMIT = 200000
DAILY_LIMIT = 500000
STARTING_BALANCE = 1000000

SESSION = {"user_id": "user_001", "account_id": "acc_001", "device_id": "dev_001"}


def get_session() -> dict:
    return SESSION.copy()


BENEFICIARIES = {
    "ben_101": {
        "name": "Rohit Sharma",
        "aliases": ["rohit"],
        "status": "active",
    },
    "ben_102": {
        "name": "Amit Verma",
        "aliases": ["amit", "brother"],
        "status": "active",
    },
    "ben_103": {
        "name": "Vikram Verma",
        "aliases": ["vikram", "brother"],
        "status": "active",
    },
    "ben_104": {
        "name": "Sarah Khan",
        "aliases": ["sarah"],
        "status": "active",
    },
    "ben_105": {
        "name": "Meera Iyer",
        "aliases": ["meera"],
        "status": "new",
    },
}


def get_beneficiaries(user_id: str) -> dict:
    if user_id == SESSION["user_id"]:
        return BENEFICIARIES.copy()
    return {}


class MockLedger:
    def __init__(self, balance: int):
        self.balance = balance
        self._lock = threading.Lock()
        self._seen_keys = set()
        self.transactions = []
        self.spent_today = 0

    def get_balance(self) -> int:
        return self.balance

    def debit(self, amount: int, beneficiary_id: str, idempotency_key: str) -> dict:
        with self._lock:
            if idempotency_key in self._seen_keys:
                return {"status": "duplicate"}
            if amount <= 0:
                return {"status": "invalid_amount"}
            if amount > self.balance:
                return {"status": "insufficient_funds"}
            self.balance -= amount
            self.spent_today += amount
            self._seen_keys.add(idempotency_key)
            self.transactions.append(
                {
                    "amount": amount,
                    "beneficiary_id": beneficiary_id,
                    "key": idempotency_key,
                }
            )
            return {"status": "ok", "balance": self.balance}


ledger = MockLedger(STARTING_BALANCE)


def reset_ledger() -> None:
    global ledger
    ledger = MockLedger(STARTING_BALANCE)
