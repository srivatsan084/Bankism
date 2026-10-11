"""Gate A (pre-filtering), Gate B (semantic guardrails), Gate E (output filtering)."""

import base64
import codecs
import collections
from decimal import Decimal
import os
import re
import threading
import time
import unicodedata

try:
    import redis
except ImportError:
    redis = None


# Gate A
MAX_CHARS = 2000
RATE_LIMIT_MAX = 20
RATE_LIMIT_WINDOW = 60

_rate_limits = {}
_rate_limit_lock = threading.Lock()
_redis_client = None


def _get_redis():
    global _redis_client
    if redis is None or not os.environ.get("REDIS_URL"):
        return None
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(os.environ["REDIS_URL"], socket_timeout=0.2)
    return _redis_client


def _redis_allow(client_id: str) -> bool:
    r = _get_redis()
    key = f"fw:rl:{client_id}"
    now = time.time()
    member = f"{now}:{os.urandom(4).hex()}"
    pipe = r.pipeline()
    pipe.zremrangebyscore(key, 0, now - RATE_LIMIT_WINDOW)
    pipe.zadd(key, {member: now})
    pipe.zcard(key)
    pipe.expire(key, RATE_LIMIT_WINDOW)
    results = pipe.execute()
    count = results[2]
    if count > RATE_LIMIT_MAX:
        r.zrem(key, member)
        return False
    return True


BLACKLIST = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(rules|instructions)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior)", re.IGNORECASE),
    re.compile(r"(reveal|show|print)\s+(your\s+)?(system\s+prompt|instructions)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now", re.IGNORECASE),
    re.compile(r"developer\s+mode", re.IGNORECASE),
    re.compile(r"override\s+(the\s+)?(limit|limits|rules|policy)", re.IGNORECASE),
]


def _block(category: str, risk: str, reason: str) -> dict:
    return {"blocked": True, "text": "", "category": category, "risk": risk, "reason": reason}


def check_rate_limit(client_id: str) -> bool:
    if _get_redis() is not None:
        try:
            return _redis_allow(client_id)
        except Exception:
            pass
    now = time.monotonic()
    with _rate_limit_lock:
        timestamps = _rate_limits.setdefault(client_id, collections.deque())
        while timestamps and now - timestamps[0] > RATE_LIMIT_WINDOW:
            timestamps.popleft()
        if len(timestamps) >= RATE_LIMIT_MAX:
            return False
        timestamps.append(now)
        return True


def reset_rate_limits() -> None:
    with _rate_limit_lock:
        _rate_limits.clear()


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(
        char
        for char in text
        if unicodedata.category(char) not in {"Cc", "Cf"} or char in {"\n", "\t"}
    )
    text = text.translate(
        str.maketrans(
            {
                "\u0430": "a",
                "\u0435": "e",
                "\u043e": "o",
                "\u0440": "p",
                "\u0441": "c",
                "\u0445": "x",
                "\u0443": "y",
                "\u0456": "i",
            }
        )
    )
    return re.sub(r"\s+", " ", text).strip()


def _blacklist_hit(text: str) -> bool:
    return any(pattern.search(text) for pattern in BLACKLIST)


def _decode_variants(text: str) -> list[str]:
    variants = [
        text.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})),
        codecs.decode(text, "rot_13"),
    ]
    for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            variants.append(base64.b64decode(token, validate=True).decode("utf-8"))
        except Exception:
            pass
    for token in re.findall(r"(?:[0-9a-fA-F]{2}){8,}", text):
        try:
            variants.append(bytes.fromhex(token).decode("utf-8"))
        except Exception:
            pass
    return variants


def gate_a(text: str, client_id: str = "anon") -> dict:
    """Run deterministic pre-filtering."""
    if len(text) > MAX_CHARS:
        return _block("none", "medium", "oversized_input")
    if not check_rate_limit(client_id):
        return _block("none", "medium", "rate_limited")
    normalized = _normalize(text)
    if _blacklist_hit(normalized):
        return _block("policy_override", "high", "override_phrase")
    if any(_blacklist_hit(variant) for variant in _decode_variants(normalized)):
        return _block("obfuscation", "high", "obfuscated_override")
    return {"blocked": False, "text": normalized, "category": "none", "risk": "low", "reason": ""}


# Gate B
ROLEPLAY_PATTERNS = [
    re.compile(r"you\s+are\s+dan", re.IGNORECASE),
    re.compile(r"\bdan\s+mode", re.IGNORECASE),
    re.compile(r"no\s+rules", re.IGNORECASE),
    re.compile(r"pretend\s+(to\s+be|you\s+are)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"without\s+(any\s+)?restrictions", re.IGNORECASE),
]

OVERRIDE_PATTERNS = [
    re.compile(r"forget\s+(your|the|all)\s+(rules|instructions)", re.IGNORECASE),
    re.compile(r"\bbypass\b", re.IGNORECASE),
    re.compile(r"disable\s+(the\s+)?(limit|check|verification|confirmation)", re.IGNORECASE),
    re.compile(r"skip\s+(the\s+)?(confirmation|verification|otp)", re.IGNORECASE),
    re.compile(r"new\s+instructions", re.IGNORECASE),
]

MEMO_PATTERNS = [
    re.compile(r"\b(system|assistant|developer)\s*:", re.IGNORECASE),
    re.compile(r"change\s+(the\s+)?(recipient|beneficiary|account)", re.IGNORECASE),
    re.compile(r"ignore\s+(previous|all|the\s+above)", re.IGNORECASE),
    re.compile(r"instead\s+(send|transfer|pay)", re.IGNORECASE),
    re.compile(r"transfer\s+(all|everything)", re.IGNORECASE),
    re.compile(r"new\s+instructions", re.IGNORECASE),
]


def _result(
    blocked: bool,
    category: str = "none",
    risk: str = "low",
    reason: str = "",
    card_detected: bool = False,
) -> dict:
    return {
        "blocked": blocked,
        "category": category,
        "risk": risk,
        "reason": reason,
        "card_detected": card_detected,
    }


def _luhn_valid(digits: str) -> bool:
    total = 0
    reverse_digits = digits[::-1]
    for index, char in enumerate(reverse_digits):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _has_card(text: str) -> bool:
    for match in re.findall(r"(?:\d[ -]?){13,19}", text):
        digits = re.sub(r"\D", "", match)
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True
    return False


def gate_b(text: str) -> dict:
    """Run semantic guardrails."""
    if _has_card(text):
        return _result(True, "none", "high", "card_data_detected", True)
    if any(pattern.search(text) for pattern in ROLEPLAY_PATTERNS):
        return _result(True, "roleplay_jailbreak", "high", "roleplay_pattern")
    if any(pattern.search(text) for pattern in OVERRIDE_PATTERNS):
        return _result(True, "policy_override", "high", "override_pattern")
    return _result(False)


def scan_untrusted_text(text: str) -> dict:
    for pattern in MEMO_PATTERNS:
        if pattern.search(text):
            return _result(True, "memo_injection", "high", "instruction_in_data")
    return _result(False)


def parse_amount(text: str) -> int | None:
    matches = re.findall(r"(\d[\d,]*(?:\.\d+)?)\s*(lakhs?|lacs?|crores?)?", text.lower())
    if len(matches) != 1:
        return None
    number, multiplier_name = matches[0]
    value = Decimal(number.replace(",", ""))
    if multiplier_name.startswith(("lakh", "lac")):
        value *= Decimal(100000)
    elif multiplier_name.startswith("crore"):
        value *= Decimal(10000000)
    return int(value)


# Gate E
LEAK_MARKERS = ["system prompt", "my instructions", "you are an untrusted parser"]
BLOCKED_OUTPUT_MESSAGE = "I can't help with that."


def gate_e(output: str) -> str:
    """Run output filtering."""
    if any(marker in output.lower() for marker in LEAK_MARKERS):
        return BLOCKED_OUTPUT_MESSAGE
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", output)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"https?://\S+", "[link removed]", text)
    text = re.sub(
        r"\d(?:[ -]?\d){12,18}",
        lambda match: "[REDACTED]"
        if _luhn_valid(re.sub(r"\D", "", match.group(0)))
        else match.group(0),
        text,
    )
    text = re.sub(r"\s+", " ", text)
    return text.strip()
