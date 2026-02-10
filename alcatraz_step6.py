#!/usr/bin/env python3
"""
ALCATRAZ Agent Jail OS — Step 6 (Read vs Trade Mode)

Includes:
- Step 1: Blocked intents
- Step 2: Rate limiting
- Step 3: Polling timeout
- Step 4: Chain allowlist
- Step 5: Max USD value
- Step 6: Read-only vs Trade mode

Run:
  python3 alcatraz_step6.py
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

class PolicyViolation(Exception): pass

@dataclass
class Capability:
    name: str
    expires: float
    scope: Dict[str, Any]
    def valid(self): return time.time() <= self.expires

@dataclass
class CapabilitySet:
    caps: Dict[str, Capability] = field(default_factory=dict)
    def require(self, name):
        cap = self.caps.get(name)
        if not cap: raise PolicyViolation(f"CAP_MISSING:{name}")
        if not cap.valid(): raise PolicyViolation(f"CAP_EXPIRED:{name}")
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
# TOOL GATE — BANKR JAIL (STEP 1–6)
# =========================================================

class ToolGate:
    def __init__(self, caps, audit, kill):
        self.caps = caps
        self.audit = audit
        self.kill = kill
        self.calls = []

    def bankr_prompt(self, prompt: str) -> dict:
        cap = self.caps.require("bankr.use")
        p = prompt.lower()

        # STEP 2 — RATE LIMIT
        now = time.time()
        self.calls = [t for t in self.calls if now - t < 60]
        if len(self.calls) >= cap.scope.get("max_calls_per_min", 0):
            self.kill.trip("BANKR_DENIED:RATE_LIMIT")
        self.calls.append(now)

        # STEP 6 — READ vs TRADE MODE
        trade_words = ["swap", "buy", "sell", "transfer", "approve", "bridge", "stake"]
        mode = cap.scope.get("mode", "read")

        if mode == "read" and any(w in p for w in trade_words):
            self.audit.write(
                "tool_denied",
                tool="bankr",
                reason="trade_in_read_mode",
                prompt=prompt,
            )
            self.kill.trip("BANKR_DENIED:READ_ONLY_MODE")

        # STEP 4 — CHAIN ALLOWLIST
        allowed = cap.scope.get("allowed_chains", [])
        if "ethereum" in p and "ethereum" not in allowed:
            self.kill.trip("BANKR_DENIED:CHAIN_NOT_ALLOWED:ethereum")

        # STEP 5 — MAX USD
        max_usd = cap.scope.get("max_usd", 0)
        if max_usd:
            amounts = re.findall(r"\$?\s?(\d+(?:,\d{3})*)", p)
            for a in amounts:
                if float(a.replace(",", "")) > max_usd:
                    self.kill.trip("BANKR_DENIED:MAX_USD_EXCEEDED")

        # BANKR CALL
        api_key = os.environ.get("BANKR_API_KEY")
        if not api_key:
            self.kill.trip("BANKR_API_KEY_MISSING")

        req = urllib.request.Request(
            "https://api.bankr.bot/agent/prompt",
            data=json.dumps({"prompt": prompt}).encode(),
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req) as r:
            job = json.loads(r.read())

        job_id = job.get("jobId")
        start = time.time()

        # STEP 3 — POLLING TIMEOUT
        while True:
            if time.time() - start > cap.scope.get("poll_timeout_s", 60):
                self.kill.trip("BANKR_DENIED:POLL_TIMEOUT")

            poll = urllib.request.Request(
                f"https://api.bankr.bot/agent/job/{job_id}",
                headers={"X-API-Key": api_key},
            )
            with urllib.request.urlopen(poll) as r:
                res = json.loads(r.read())

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
    p.start(); p.join(90)
    return rq.get()


# =========================================================
# DEMO
# =========================================================

if __name__ == "__main__":

    AGENT_CODE = r'''
def run(TASK, TOOLS):
    return TOOLS.bankr_prompt("What is the price of ETH on Base?")
'''

    result = run_agent(
        AGENT_CODE,
        grants=[
            ("bankr.use", 60, {
                "mode": "read",                # ✅ STEP 6
                "allowed_chains": ["base"],
                "max_calls_per_min": 5,
                "max_usd": 100,
                "poll_timeout_s": 60,
            })
        ],
    )

    print("RESULT:", result)
