#!/usr/bin/env python3
"""
ALCATRAZ Agent Jail OS — STEP 8 (Human Approval Gate) — FIXED

✔ Separate queues (no race condition)
✔ One-time approval tokens
✔ Timeout enforcement
✔ Full audit trail

Run:
  python3 alcatraz_step8_fixed.py
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
        with open(self.path, "a", encoding="utf-8") as f:
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
    def __init__(self, audit: AuditLog):
        self.audit = audit
        self.tripped = False

    def trip(self, reason: str):
        if not self.tripped:
            self.tripped = True
            self.audit.write("CELL_KILLED", reason=reason)
        raise PolicyViolation(reason)


# =========================================================
# TOOL GATE — STEP 8 (FIXED)
# =========================================================

class ToolGate:
    def __init__(
        self,
        caps: CapabilitySet,
        audit: AuditLog,
        kill: KillSwitch,
        approval_req_q: Queue,
        approval_res_q: Queue,
    ):
        self.caps = caps
        self.audit = audit
        self.kill = kill
        self.approval_req_q = approval_req_q
        self.approval_res_q = approval_res_q
        self.calls = []

    def _require_human_approval(self, cap: Capability, prompt: str):
        token = f"appr_{int(time.time())}_{os.getpid()}"
        timeout_s = int(cap.scope.get("approval_timeout_s", 30))

        self.audit.write(
            "approval_requested",
            token=token,
            prompt=prompt,
            timeout_s=timeout_s,
        )

        # Send request to controller
        self.approval_req_q.put({
            "token": token,
            "prompt": prompt,
            "timeout_s": timeout_s,
        })

        start = time.time()
        while True:
            if time.time() - start > timeout_s:
                self.kill.trip("BANKR_DENIED:HUMAN_APPROVAL_TIMEOUT")

            try:
                msg = self.approval_res_q.get_nowait()
            except Exception:
                msg = None

            if msg and msg.get("token") == token:
                if msg.get("decision") == "approve":
                    self.audit.write("approval_granted", token=token)
                    return
                else:
                    self.kill.trip("BANKR_DENIED:HUMAN_APPROVAL_DENIED")

            time.sleep(0.1)

    def bankr_prompt(self, prompt: str) -> dict:
        cap = self.caps.require("bankr.use")
        p = prompt.lower()

        # Detect trade intent
        trade_words = ["buy", "sell", "swap", "transfer", "approve", "bridge", "stake"]
        is_trade = any(w in p for w in trade_words)

        # STEP 8 — require approval for trades
        if is_trade and cap.scope.get("approval_required", False):
            self._require_human_approval(cap, prompt)

        self.audit.write("tool_attempt", tool="bankr", prompt=prompt)

        api_key = os.environ.get("BANKR_API_KEY")
        if not api_key:
            self.kill.trip("BANKR_API_KEY_MISSING")

        req = urllib.request.Request(
            "https://api.bankr.bot/agent/prompt",
            data=json.dumps({"prompt": prompt}).encode(),
            headers={
                "X-API-Key": api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as r:
            job = json.loads(r.read().decode())

        return job


# =========================================================
# AGENT + CONTROLLER
# =========================================================

def agent_cell(code, cap_dict, audit_path, approval_req_q, approval_res_q, result_q):
    audit = AuditLog(audit_path)
    caps = CapabilitySet({
        k: Capability(k, v["expires"], v["scope"])
        for k, v in cap_dict.items()
    })
    kill = KillSwitch(audit)
    tools = ToolGate(caps, audit, kill, approval_req_q, approval_res_q)

    try:
        env = {"__builtins__": {"print": print}, "TOOLS": tools}
        exec(code, env, env)
        out = env["run"]({}, tools)
        result_q.put({"ok": True, "output": out})
    except Exception as e:
        result_q.put({"ok": False, "error": str(e)})


def run_agent(code, grants):
    now = time.time()
    cap_dict = {
        name: {"expires": now + ttl, "scope": scope}
        for name, ttl, scope in grants
    }

    approval_req_q = Queue()
    approval_res_q = Queue()
    result_q = Queue()

    p = Process(
        target=agent_cell,
        args=(code, cap_dict, "./audit/alcatraz.jsonl",
              approval_req_q, approval_res_q, result_q),
        daemon=True,
    )
    p.start()

    # Controller loop
    while True:
        if not result_q.empty():
            return result_q.get()

        try:
            req = approval_req_q.get_nowait()
        except Exception:
            req = None

        if req:
            token = req["token"]
            prompt = req["prompt"]
            timeout_s = req["timeout_s"]

            print("\n=== HUMAN APPROVAL REQUIRED ===")
            print("Prompt:", prompt)
            print("To approve:  APPROVE", token)
            print("To deny:     DENY", token)
            print(f"(auto-timeout in {timeout_s}s)\n")

            user = input("> ").strip()
            if user == f"APPROVE {token}":
                approval_res_q.put({"token": token, "decision": "approve"})
            else:
                approval_res_q.put({"token": token, "decision": "deny"})

        time.sleep(0.05)


# =========================================================
# DEMO
# =========================================================

if __name__ == "__main__":

    AGENT_CODE = r'''
def run(TASK, TOOLS):
    return TOOLS.bankr_prompt("Buy $50 ETH on Base")
'''

    result = run_agent(
        AGENT_CODE,
        grants=[
            ("bankr.use", 120, {
                "approval_required": True,
                "approval_timeout_s": 30,
            })
        ],
    )

    print("\nRESULT:", result)
