"""FastAPI entrypoint. Wires /support, /payments, /parsing through gates A to E."""

import os
from pathlib import Path
import threading
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

import enforcement
import gates
import mocks
import planner

app = FastAPI(title="AI Firewall for Banking")

INDEX_HTML = Path(__file__).parent / "index.html"


@app.get("/", response_class=HTMLResponse)
def index():
    if INDEX_HTML.exists():
        return HTMLResponse(content=INDEX_HTML.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Bankism AI Firewall</h1><p><a href='/docs'>Swagger API Docs</a></p>")


@app.get("/health")
def health():
    return {"status": "ok"}


SERVICE_CONFIG = {
    "support": {"max_concurrent": 50},
    "payments": {"max_concurrent": 10},
    "parsing": {"max_concurrent": 20},
}

_raw_services = os.environ.get("FIREWALL_SERVICES", "support,payments,parsing").split(",")
ENABLED = [s.strip() for s in _raw_services if s.strip() in SERVICE_CONFIG]
if not ENABLED:
    raise RuntimeError("no valid services")

_raw_killed = os.environ.get("FIREWALL_KILL", "").split(",")
KILLED = {s.strip() for s in _raw_killed if s.strip() in SERVICE_CONFIG}


def set_kill(service: str, on: bool) -> None:
    if on:
        KILLED.add(service)
    else:
        KILLED.discard(service)


SEMAPHORES = {
    name: threading.BoundedSemaphore(cfg["max_concurrent"])
    for name, cfg in SERVICE_CONFIG.items()
}

STATIC_SUPPORT_MESSAGE = "Service is busy. Please check the FAQ."


def _verdict(
    decision,
    risk,
    category,
    rationale,
    trace,
    intent=None,
    message="",
    token=None,
    data=None,
) -> dict:
    return {
        "decision": decision,
        "risk_level": risk,
        "threat_category": category,
        "rationale": rationale,
        "extracted_intent": intent,
        "gate_trace": trace,
        "user_message": gates.gate_e(message),
        "confirmation_token": token,
        "data": data,
    }


USER_MESSAGES = {
    "approved": "Request accepted.",
    "blocked": "This request cannot be processed.",
    "needs_clarification": "Please clarify your request.",
}


def _shed(service, reason) -> dict:
    return _verdict(
        "blocked",
        "medium",
        "none",
        reason,
        ["S:" + reason],
        None,
        STATIC_SUPPORT_MESSAGE if service == "support" else USER_MESSAGES["blocked"],
    )


def run_pipeline(text: str, service: str, client_id: str = "anon", token: str | None = None) -> dict:
    trace = []
    a = gates.gate_a(text, f"{service}:{client_id}")
    if a["blocked"]:
        trace.append("A:block")
        return _verdict(
            "blocked",
            a["risk"],
            a["category"],
            a["reason"],
            trace,
            message=USER_MESSAGES["blocked"],
        )
    trace.append("A:pass")
    clean = a["text"]
    if service == "parsing":
        s = gates.scan_untrusted_text(clean)
        if s["blocked"]:
            trace.append("B:block")
            return _verdict(
                "blocked",
                s["risk"],
                s["category"],
                s["reason"],
                trace,
                message=USER_MESSAGES["blocked"],
            )
        trace.append("B:pass")
        return _verdict(
            "approved",
            "low",
            "none",
            "parsed_no_execution",
            trace,
            {"amount": gates.parse_amount(clean)},
            USER_MESSAGES["approved"],
        )
    b = gates.gate_b(clean)
    if b["blocked"]:
        trace.append("B:block")
        return _verdict(
            "blocked",
            b["risk"],
            b["category"],
            b["reason"],
            trace,
            message=USER_MESSAGES["blocked"],
        )
    trace.append("B:pass")
    c = planner.extract_intent(clean)
    if not c["ok"]:
        trace.append("C:ambiguous")
        return _verdict(
            "needs_clarification",
            "medium",
            c["category"],
            c["reason"],
            trace,
            message=USER_MESSAGES["needs_clarification"],
        )
    trace.append("C:extracted")
    intent = c["intent"]
    if (
        service == "support"
        and intent["action"] not in {"balance", "statement"}
        or service == "payments"
        and intent["action"] != "transfer"
    ):
        trace.append("S:block")
        return _verdict(
            "blocked",
            "medium",
            "none",
            "action_not_allowed_for_service",
            trace,
            message=USER_MESSAGES["blocked"],
        )
    d = enforcement.enforce(intent, mocks.get_session(), token)
    trace.append("D:" + d["reason"])
    extracted_intent = None
    if d["decision"] not in {"blocked", "needs_clarification"}:
        extracted_intent = {
            "action": intent["action"],
            "amount": intent["amount"],
            "currency": "INR",
            "beneficiary_id": d["params"]["beneficiary_id"] if d["params"] else None,
        }
    return _verdict(
        d["decision"],
        d["risk_level"],
        d["threat_category"],
        d["reason"],
        trace,
        extracted_intent,
        USER_MESSAGES[d["decision"]],
        d["confirmation_token"],
        d["data"],
    )


def safe_run(text, service, client_id, token) -> dict:
    if service not in SEMAPHORES:
        return _shed(service, "unknown_service")
    if service in KILLED:
        return _shed(service, "service_disabled")
    if not SEMAPHORES[service].acquire(blocking=False):
        return _shed(service, "overloaded")
    try:
        return run_pipeline(text, service, client_id, token)
    except Exception:
        return _verdict("blocked", "high", "none", "internal_error", ["ERR"], None, USER_MESSAGES["blocked"])
    finally:
        SEMAPHORES[service].release()


def _status_for(rationale: str) -> int:
    if rationale == "rate_limited":
        return 429
    if rationale in {"overloaded", "service_disabled"}:
        return 503
    return 200


def _respond(verdict: dict) -> JSONResponse:
    return JSONResponse(content=verdict, status_code=_status_for(verdict["rationale"]))


class Req(BaseModel):
    text: str
    token: Optional[str] = None


if "support" in ENABLED:
    @app.post("/support")
    def support(req: Req, request: Request):
        client_id = request.client.host if request.client else "anon"
        return _respond(safe_run(req.text, "support", client_id, req.token))


if "payments" in ENABLED:
    @app.post("/payments")
    def payments(req: Req, request: Request):
        client_id = request.client.host if request.client else "anon"
        return _respond(safe_run(req.text, "payments", client_id, req.token))


if "parsing" in ENABLED:
    @app.post("/parsing")
    def parsing(req: Req, request: Request):
        client_id = request.client.host if request.client else "anon"
        return _respond(safe_run(req.text, "parsing", client_id, req.token))
