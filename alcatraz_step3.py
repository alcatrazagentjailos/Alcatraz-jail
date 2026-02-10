
#!/usr/bin/env python3
"""
ALCATRAZ Agent Jail OS
Steps implemented:
- Step 1: Hard intent blocking
- Step 2: Rate limiting
- Step 3: Polling timeout jail

Run:
  python3 alcatraz_step3_full.py
"""

from __future__ import annotations
from dotenv import load_dotenv
load_dotenv("/home/bbt/alcatraz/.env")

import os, time, json, urllib.request
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
            f.write(json.dumps({
                "ts": time.time(),
                "event": event,
                **data
            }) + "\n")


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
# TOOL GATE — BANKR JAIL (STEP 1–3)
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
        self._bankr_call_times = [
            t for t in self._bankr_call_times if now - t < 60
        ]
        max_calls = int(cap.scope.get("max_calls_per_min", 0))
        if max_calls and len(self._bankr_call_times) >= max_calls:
            self.audit.write(
                "tool_denied",
                tool="bankr",
                reason="rate_limit",
                max_calls_per_min=max_calls,
                calls_last_60s=len(self._bankr_call_times),
                prompt=prompt,
            )
            self.kill.trip("BANKR_DENIED:RATE_LIMIT")
        self._bankr_call_times.append(now)

        # --------------- STEP 1: BLOCKED INTENTS ------------
        for bad in cap.scope.get("blocked_actions", []):
            if bad in p:
                self.audit.write(
                    "tool_denied",
                    tool="bankr",
                    reason="blocked_action",
                    keyword=bad,
                    prompt=prompt,
                )
                self.kill.trip(f"BANKR_BLOCKED_ACTION:{bad}")

        self.audit.write("tool_attempt", tool="bankr", prompt=prompt)

        # ---------------- BANKR PROMPT CALL -----------------
        api_key = os.environ.get("BANKR_API_KEY")
        if not api_key:
            self.kill.trip("BANKR_API_KEY_MISSING")

        bankr_base = os.environ.get("BANKR_API_URL", "https://api.bankr.bot")
        req = urllib.request.Request(
            f"{bankr_base}/agent/prompt",
            data=json.dumps({"prompt": prompt}).encode(),
            headers={
                "X-API-Key": api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                job = json.loads(r.read().decode())
        except Exception as e:
            self.kill.trip(f"BANKR_HTTP_ERROR:{e}")

        job_id = job.get("jobId")
        if not job_id:
            self.kill.trip("BANKR_NO_JOB_ID")

        # --------------- STEP 3: POLLING TIMEOUT -------------
        poll_timeout = int(cap.scope.get("poll_timeout_s", 60))
        start = time.time()

        while True:
            if time.time() - start > poll_timeout:
                self.audit.write(
                    "tool_denied",
                    tool="bankr",
                    reason="poll_timeout",
                    timeout_s=poll_timeout,
                    jobId=job_id,
                )
                self.kill.trip("BANKR_DENIED:POLL_TIMEOUT")

            try:
                poll_req = urllib.request.Request(
                    f"{bankr_base}/agent/job/{job_id}",
                    headers={
                        "X-API-Key": api_key,
                        "Content-Type": "application/json",
                    },
                )
                with urllib.request.urlopen(poll_req, timeout=10) as r:
                    res = json.loads(r.read().decode())
            except Exception as e:
                self.kill.trip(f"BANKR_POLL_ERROR:{e}")

            status = res.get("status")
            self.audit.write("job_poll", jobId=job_id, status=status)

            if status == "completed":
                self.audit.write("tool_ok", tool="bankr", jobId=job_id)
                return res

            if status in ("failed", "cancelled", "error"):
                self.kill.trip(f"BANKR_JOB_{status.upper()}")

            time.sleep(2)


# =========================================================
# AGENT CELL + CONTROLLER
# =========================================================

def agent_cell(code, cap_dict, audit_path, kq, rq):
    audit = AuditLog(audit_path)
    caps = CapabilitySet({
        k: Capability(k, v["expires"], v["scope"])
        for k, v in cap_dict.items()
    })
    kill = KillSwitch(audit, kq)
    tools = ToolGate(caps, audit, kill)

    try:
        env = {
            "__builtins__": {"print": print},
            "TOOLS": tools,
            "TASK": {},
        }
        exec(code, env, env)
        out = env["run"](env["TASK"], tools)
        rq.put({"ok": True, "output": out})
    except Exception as e:
        rq.put({"ok": False, "error": str(e)})

def run_agent(code, grants):
    audit = AuditLog()
    now = time.time()
    cap_dict = {
        n: {"expires": now + ttl, "scope": scope}
        for n, ttl, scope in grants
    }
    kq, rq = Queue(), Queue()
    p = Process(
        target=agent_cell,
        args=(code, cap_dict, audit.path, kq, rq),
        daemon=True,
    )
    p.start()
    p.join(90)
    return rq.get()


# =========================================================
# DEMO
# =========================================================

if __name__ == "__main__":

    AGENT_CODE = r'''
def run(TASK, TOOLS):
    return TOOLS.bankr_prompt("What is the price of ETH on solana?")
'''

    result = run_agent(
    AGENT_CODE,
    grants=[
        ("bankr.use", 60, {
            "blocked_actions": [
                # ---- existing blocked actions ----
                "transfer",
                "withdraw",
                "approve",
                "bridge",
                "stake",
                "unstake",
                "base",
                "ethereum",
                "bsc",
                "polygon",
            ],
            "max_calls_per_min": 5,
            "poll_timeout_s": 60,
        })
    ],
)

print("RESULT:", result)

