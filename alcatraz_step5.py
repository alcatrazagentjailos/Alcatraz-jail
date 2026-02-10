#!/usr/bin/env python3
"""
ALCATRAZ Agent Jail OS — Step 5 (Max USD Jail)

Includes:
- Step 1: Blocked intents
- Step 2: Rate limiting
- Step 3: Polling timeout
- Step 4: Chain allowlist
- Step 5: Max USD value

Run:
  python3 alcatraz_step5.py
"""

from __future__ import annotations
from dotenv import load_dotenv
load_dotenv("/home/bbt/alcatraz/.env")

import os, time, json, re, urllib.request
from multiprocessing import Process, Queue
from dataclasses import dataclass, field
from typing import Dict, Any


# =========================================================
# AUDIT LOG
# =========================================================

class AuditLog:
    def __init__(self, path="./audit/alcatraz.jsonl"):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, event, **data):
        with open(self.path, "a") as f:
            f.write(json.dumps({"ts": time.time(), "event": event, **data}) + "\n")


# =========================================================
# CAPABILITIES
# =========================================================

class PolicyViolation(Exception):
    pass

@dataclass
class Capability:
    name: str
    expires: float
    scope: Dict[str, Any]

    def valid(self):
        return time.time() <= self.expires

@dataclass
class CapabilitySet:
    caps: Dict[str, Capability] = field(default_factory=dict)

    def require(self, name):
        cap = self.caps.get(name)
        if not cap:
            raise PolicyViolation(f"CAP_MISSING:{name}")
        if not cap.valid():
            raise PolicyViolation(f"CAP_EXPIRED:{name}")
        return cap


# =========================================================
# KILL SWITCH
# =========================================================

class KillSwitch:
    def __init__(self, audit, q):
        self.audit = audit
        self.q = q
        self.tripped = False

    def trip(self, reason):
        if not self.tripped:
            self.tripped = True
            self.audit.write("CELL_KILLED", reason=reason)
            self.q.put(reason)
        raise PolicyViolation(reason)


# =========================================================
# TOOL GATE — BANKR JAIL (STEP 1–5)
# =========================================================

class ToolGate:
    def __init__(self, caps, audit, kill):
        self.caps = caps
        self.audit = audit
        self.kill = kill
        self._bankr_call_times = []

    def bankr_prompt(self, prompt: str) -> dict:
        cap = self.caps.require("bankr.use")
        p = prompt.lower()

        # ---------------- STEP 2: RATE LIMIT ----------------
        now = time.time()
        self._bankr_call_times = [t for t in self._bankr_call_times if now - t < 60]
        max_calls = int(cap.scope.get("max_calls_per_min", 0))
        if max_calls and len(self._bankr_call_times) >= max_calls:
            self.kill.trip("BANKR_DENIED:RATE_LIMIT")
        self._bankr_call_times.append(now)

        # ---------------- STEP 1: BLOCKED INTENTS ------------
        for bad in cap.scope.get("blocked_actions", []):
            if bad in p:
                self.kill.trip(f"BANKR_BLOCKED_ACTION:{bad}")

        # ---------------- STEP 4: CHAIN ALLOWLIST ------------
        allowed_chains = [c.lower() for c in cap.scope.get("allowed_chains", [])]
        chains = {
            "ethereum": ["ethereum", "mainnet"],
            "base": ["base"],
            "solana": ["solana", "sol"],
        }

        mentioned = None
        for c, aliases in chains.items():
            if any(a in p for a in aliases):
                mentioned = c
                break

        if mentioned and allowed_chains and mentioned not in allowed_chains:
            self.kill.trip(f"BANKR_DENIED:CHAIN_NOT_ALLOWED:{mentioned}")

        # ---------------- STEP 5: MAX USD -------------------
        max_usd = float(cap.scope.get("max_usd", 0))
        if max_usd > 0:
            amounts = re.findall(r"\$?\s?(\d+(?:,\d{3})*(?:\.\d+)?)\s?(usd|dollars)?", p)
            for amt, _ in amounts:
                value = float(amt.replace(",", ""))
                if value > max_usd:
                    self.audit.write(
                        "tool_denied",
                        tool="bankr",
                        reason="max_usd_exceeded",
                        value=value,
                        max_usd=max_usd,
                        prompt=prompt,
                    )
                    self.kill.trip("BANKR_DENIED:MAX_USD_EXCEEDED")

        self.audit.write("tool_attempt", tool="bankr", prompt=prompt)
        # ---------------- BANKR CALL -------------------------
        api_key = os.environ.get("BANKR_API_KEY")
        if not api_key:
            self.kill.trip("BANKR_API_KEY_MISSING")

        bankr_base = os.environ.get("BANKR_API_URL", "https://api.bankr.bot")
        req = urllib.request.Request(
            f"{bankr_base}/agent/prompt",
            data=json.dumps({"prompt": prompt}).encode(),
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as r:
            job = json.loads(r.read().decode())

        job_id = job.get("jobId")
        if not job_id:
            self.kill.trip("BANKR_NO_JOB_ID")

        # ---------------- STEP 3: POLLING -------------------
        start = time.time()
        timeout = int(cap.scope.get("poll_timeout_s", 60))

        while True:
            if time.time() - start > timeout:
                self.kill.trip("BANKR_DENIED:POLL_TIMEOUT")

            poll = urllib.request.Request(
                f"{bankr_base}/agent/job/{job_id}",
                headers={"X-API-Key": api_key},
            )
            with urllib.request.urlopen(poll, timeout=10) as r:
                res = json.loads(r.read().decode())

            if res.get("status") == "completed":
                return res

            time.sleep(2)


# =========================================================
# AGENT + CONTROLLER
# =========================================================

def agent_cell(code, cap_dict, audit_path, kq, rq):
    audit = AuditLog(audit_path)
    caps = CapabilitySet({k: Capability(k, v["expires"], v["scope"]) for k, v in cap_dict.items()})
    kill = KillSwitch(audit, kq)
    tools = ToolGate(caps, audit, kill)

    try:
        env = {"__builtins__": {"print": print}, "TOOLS": tools}
        exec(code, env, env)
        rq.put({"ok": True, "output": env["run"]({}, tools)})
    except Exception as e:
        rq.put({"ok": False, "error": str(e)})

def run_agent(code, grants):
    now = time.time()
    cap_dict = {n: {"expires": now + ttl, "scope": scope} for n, ttl, scope in grants}
    kq, rq = Queue(), Queue()
    p = Process(target=agent_cell, args=(code, cap_dict, "./audit/alcatraz.jsonl", kq, rq))
    p.start()
    p.join(90)
    return rq.get()


# =========================================================
# DEMO
# =========================================================

if __name__ == "__main__":
    import os

    TEST_PROMPT = os.environ.get("TEST_PROMPT", "What is the price of SOL on Solana devnet for $10?")
    ALLOWED_CHAINS_ENV = os.environ.get("ALLOWED_CHAINS", "solana")
    ALLOWED_CHAINS = [c.strip().lower() for c in ALLOWED_CHAINS_ENV.split(",") if c.strip()]

    # write prompt to file so mock server can inspect it (simple IPC for local tests)
    try:
        with open('last_prompt.txt', 'w') as f:
            f.write(TEST_PROMPT)
    except Exception:
        pass

    AGENT_CODE = rf'''
def run(TASK, TOOLS):
    return TOOLS.bankr_prompt("{TEST_PROMPT}")
'''

    # Allow overriding max USD via env for tests
    try:
        MAX_USD = float(os.environ.get("MAX_USD", "101"))
    except Exception:
        MAX_USD = 101.0

    try:
        POLL_TIMEOUT = int(os.environ.get("POLL_TIMEOUT", "3"))
    except Exception:
        POLL_TIMEOUT = 3

    result = run_agent(
        AGENT_CODE,
        grants=[
            ("bankr.use", 60, {
                "blocked_actions": ["transfer", "withdraw", "approve", "bridge"],
                "max_calls_per_min": 5,
                "poll_timeout_s": 60,
                "allowed_chains": ALLOWED_CHAINS,
                "max_usd": MAX_USD,
                "poll_timeout_s": POLL_TIMEOUT,
            })
        ],
    )

    print("RESULT:", result)
