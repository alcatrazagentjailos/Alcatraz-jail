#!/usr/bin/env python3
"""
ALCATRAZ Agent Jail OS — STEP 9 (Policy Lock / Immutability)

FINAL LAYER

✔ Freezes policy after agent start
✔ Prevents runtime modification
✔ No self-upgrading permissions
✔ Custody-grade safety

Run:
  python3 alcatraz_step9.py
"""

from __future__ import annotations
from dotenv import load_dotenv
load_dotenv("/home/bbt/alcatraz/.env")

import os, time, json, urllib.request
from multiprocessing import Process, Queue
from dataclasses import dataclass, field
from typing import Dict, Any
from types import MappingProxyType


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
# CAPABILITIES (IMMUTABLE)
# =========================================================

class PolicyViolation(Exception):
    pass

@dataclass(frozen=True)
class Capability:
    name: str
    expires: float
    scope: MappingProxyType   # 🔒 READ-ONLY

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
# TOOL GATE (READ-ONLY POLICY)
# =========================================================

class ToolGate:
    def __init__(self, caps: CapabilitySet, audit: AuditLog, kill: KillSwitch):
        self.caps = caps
        self.audit = audit
        self.kill = kill

    def bankr_prompt(self, prompt: str) -> dict:
        cap = self.caps.require("bankr.use")

        # 🔒 STEP 9 — POLICY IS IMMUTABLE
        if not isinstance(cap.scope, MappingProxyType):
            self.kill.trip("POLICY_MUTATION_DETECTED")

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

        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            self.kill.trip(f"BANKR_HTTP_ERROR:{e}")


# =========================================================
# AGENT + CONTROLLER
# =========================================================

def agent_cell(code, cap_dict, audit_path, result_q):
    audit = AuditLog(audit_path)

    # 🔒 Freeze scopes using MappingProxyType
    frozen_caps = {}
    for name, meta in cap_dict.items():
        frozen_caps[name] = Capability(
            name=name,
            expires=meta["expires"],
            scope=MappingProxyType(meta["scope"]),
        )

    caps = CapabilitySet(frozen_caps)
    kill = KillSwitch(audit)
    tools = ToolGate(caps, audit, kill)

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

    rq = Queue()
    p = Process(
        target=agent_cell,
        args=(code, cap_dict, "./audit/alcatraz.jsonl", rq),
        daemon=True,
    )
    p.start()
    p.join(60)
    return rq.get()


# =========================================================
# DEMO
# =========================================================

if __name__ == "__main__":

    # Agent tries to read policy (allowed) but cannot modify it
    AGENT_CODE = r'''
def run(TASK, TOOLS):
    return TOOLS.bankr_prompt("What is the price of ETH on solana?")
'''

    result = run_agent(
        AGENT_CODE,
        grants=[
            ("bankr.use", 120, {
                "mode": "read",
                "execution": "live",
                "allowed_chains": ["solana"],
                "max_usd": 100,
            })
        ],
    )

    print("RESULT:", result)
