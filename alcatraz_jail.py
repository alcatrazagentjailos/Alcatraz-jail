#!/usr/bin/env python3
"""
ALCATRAZ Agent Jail OS
Jails BankrBot usage via capability-gated ToolGate

Run:
  export BANKR_API_KEY="YOUR_KEY"
  python3 alcatraz_jail.py
"""

from __future__ import annotations
from dotenv import load_dotenv
load_dotenv()
import ast, os, json, time, queue, signal, traceback
from multiprocessing import Process, Queue
from dataclasses import dataclass, field
from typing import Dict, Any, List, Tuple, Optional
import urllib.request, urllib.error


# =========================
# AUDIT LOG
# =========================

class AuditLog:
    def __init__(self, path="./audit/alcatraz.jsonl"):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def write(self, event, **data):
        with open(self.path, "a") as f:
            f.write(json.dumps({"ts": time.time(), "event": event, **data}) + "\n")


# =========================
# CAPABILITIES
# =========================

class PolicyViolation(Exception): pass

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


# =========================
# AST VALIDATION
# =========================

FORBIDDEN_NAMES = {
    "__import__", "eval", "exec", "open", "compile",
    "globals", "locals", "vars", "dir", "help",
    "os", "sys", "subprocess", "socket",
}

ALLOWED_NODES = {
    ast.Module, ast.Expr, ast.Assign, ast.Return,
    ast.FunctionDef, ast.arguments, ast.arg,
    ast.Name, ast.Load, ast.Store, ast.Constant,
    ast.Call, ast.Attribute,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div,
    ast.Compare, ast.Eq, ast.NotEq,
    ast.If, ast.For, ast.While,
    ast.List, ast.Tuple, ast.Dict,
}

def validate_code(src):
    tree = ast.parse(src)
    for n in ast.walk(tree):

        if isinstance(n, (ast.Import, ast.ImportFrom)):
            raise PolicyViolation("IMPORT_BLOCKED")

        if type(n) not in ALLOWED_NODES:
            raise PolicyViolation(f"SYNTAX_BLOCKED:{type(n).__name__}")

        if isinstance(n, ast.Name) and n.id in FORBIDDEN_NAMES:
            raise PolicyViolation(f"FORBIDDEN_NAME:{n.id}")

        if isinstance(n, ast.Attribute):
            if n.attr.startswith("__"):
                raise PolicyViolation("DUNDER_BLOCKED")


# =========================
# KILL SWITCH
# =========================

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


# =========================
# TOOL GATE (BANKR JAIL)
# =========================

class ToolGate:
    def __init__(self, caps, audit, kill):
        self.caps = caps
        self.audit = audit
        self.kill = kill
        self.calls = []

    def _rate_limit(self, cap):
        now = time.time()
        self.calls = [t for t in self.calls if now - t < 60]
        max_calls = cap.scope.get("max_calls_per_min", 0)
        if max_calls and len(self.calls) >= max_calls:
            self.kill.trip("BANKR_RATE_LIMIT")
        self.calls.append(now)

    def bankr_prompt(self, prompt: str) -> dict:
        self.audit.write("tool_attempt", tool="bankr", prompt=prompt)

        cap = self.caps.require("bankr.use")
        self._rate_limit(cap)

        p = prompt.lower()

        # Block dangerous actions
        for bad in cap.scope.get("blocked_actions", []):
            if bad in p:
                self.kill.trip("BANKR_BLOCKED_ACTION")

        # Enforce max USD
        max_usd = cap.scope.get("max_usd", 0)
        for tok in p.replace(",", "").split():
            if tok.startswith("$"):
                try:
                    if float(tok[1:]) > max_usd:
                        self.kill.trip("BANKR_MAX_USD_EXCEEDED")
                except:
                    pass

        # Call Bankr API
        api_key = os.environ.get("BANKR_API_KEY")
        if not api_key:
            self.kill.trip("BANKR_API_KEY_MISSING")

        req = urllib.request.Request(
            "https://api.bankr.bot/agent/prompt",
            data=json.dumps({"prompt": prompt}).encode(),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_key,
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                job = json.loads(r.read())
        except Exception as e:
            self.kill.trip(f"BANKR_HTTP_ERROR:{e}")

        job_id = job.get("jobId")
        if not job_id:
            self.kill.trip("BANKR_NO_JOB_ID")

        # Poll job
        start = time.time()
        while True:
            if time.time() - start > cap.scope.get("poll_timeout_s", 60):
                self.kill.trip("BANKR_POLL_TIMEOUT")

            with urllib.request.urlopen(
                urllib.request.Request(
                    f"https://api.bankr.bot/agent/job/{job_id}",
                    headers={"X-API-Key": api_key}
                ),
                timeout=8
            ) as r:
                res = json.loads(r.read())

            status = res.get("status")
            self.audit.write("bankr_poll", jobId=job_id, status=status)

            if status == "completed":
                return res
            if status in ("failed", "cancelled"):
                self.kill.trip(f"BANKR_JOB_{status.upper()}")

            time.sleep(2)


# =========================
# AGENT CELL
# =========================

def agent_cell(code, cap_dict, audit_path, kill_q, res_q):
    audit = AuditLog(audit_path)
    caps = CapabilitySet({
        k: Capability(k, v["expires"], v["scope"])
        for k, v in cap_dict.items()
    })
    kill = KillSwitch(audit, kill_q)
    tools = ToolGate(caps, audit, kill)

    try:
        validate_code(code)
        env = {
            "__builtins__": {"print": print, "len": len, "str": str},
            "TOOLS": tools,
            "TASK": {}
        }
        exec(code, env, env)
        out = env["run"](env["TASK"], tools)
        res_q.put({"ok": True, "output": out})
    except Exception as e:
        res_q.put({"ok": False, "error": str(e)})


# =========================
# CONTROLLER
# =========================

def run_agent(code, grants):
    audit = AuditLog()
    now = time.time()
    cap_dict = {
        n: {"expires": now + t, "scope": s}
        for n, t, s in grants
    }
    kq, rq = Queue(), Queue()
    p = Process(target=agent_cell, args=(code, cap_dict, audit.path, kq, rq))
    p.start()
    p.join(90)
    return rq.get()


# =========================
# DEMO
# =========================

if __name__ == "__main__":

    AGENT_CODE = r'''
def run(TASK, TOOLS):
    return TOOLS.bankr_prompt("What is the price of ETH on Base?")
'''

    result = run_agent(
        AGENT_CODE,
        grants=[
            ("bankr.use", 60, {
                "allowed_actions": ["price"],
                "blocked_actions": ["transfer", "withdraw", "approve", "bridge"],
                "max_usd": 101,
                "max_calls_per_min": 5,
                "poll_timeout_s": 60,
            }),
        ]
    )

    print("RESULT:", result)
