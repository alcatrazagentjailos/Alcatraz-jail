#!/usr/bin/env python3
"""
ALCATRAZ Agent Jail OS — Step 6 (Read vs Trade Mode)
- Solana chain only
- Always block: transfer/withdraw/approve/bridge/stake
- Read mode: sirf price check
- Trade mode: buy/sell/swap allowed
- Max USD: $100
- Auto-detect mode from prompt!
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

        # ---------------- STEP 1: ALWAYS BLOCKED ACTIONS ----------------
        always_blocked = ["transfer", "withdraw", "approve", "bridge", "stake", "unstake"]
        for bad in always_blocked:
            if bad in p:
                self.kill.trip(f"BANKR_BLOCKED_ACTION:{bad}")

        # ---------------- STEP 4: CHAIN ALLOWLIST ----------------
        allowed_chains = [c.lower() for c in cap.scope.get("allowed_chains", ["solana"])]
        chains = {
            "ethereum": ["ethereum", "eth", "mainnet"],
            "base": ["base"],
            "solana": ["solana", "sol"],
            "bsc": ["bsc", "binance"],
            "polygon": ["polygon", "matic"],
        }
        mentioned = None
        for chain, aliases in chains.items():
            if any(a in p for a in aliases):
                mentioned = chain
                break
        if mentioned and allowed_chains and mentioned not in allowed_chains:
            self.kill.trip(f"BANKR_DENIED:CHAIN_NOT_ALLOWED:{mentioned}")

        # ---------------- STEP 6: READ vs TRADE MODE ----------------
        mode = cap.scope.get("mode", "read")
        # Sirf yeh trade words hain - transfer/approve etc already blocked
        trade_words = ["swap", "buy", "sell"]
        
        if mode == "read":
            for word in trade_words:
                if word in p:
                    self.kill.trip("BANKR_DENIED:READ_ONLY_MODE")
        # Trade mode mein sab allow hai - kuch block nahi

        # ---------------- STEP 5: MAX USD -------------------
        max_usd = float(cap.scope.get("max_usd", 0))
        if max_usd > 0:
            amounts = re.findall(r"\$?\s?(\d+(?:,\d{3})*(?:\.\d+)?)\s?(usd|dollars)?", p)
            for amt, _ in amounts:
                value = float(amt.replace(",", ""))
                if value > max_usd:
                    self.kill.trip("BANKR_DENIED:MAX_USD_EXCEEDED")

        self.audit.write("tool_attempt", tool="bankr", prompt=prompt)

        # ---------------- BANKR CALL -------------------------
        api_key = os.environ.get("BANKR_API_KEY")
        if not api_key:
            self.kill.trip("BANKR_API_KEY_MISSING")

        # ✅ SAHI URL - /v1 HATAYA!
        bankr_base = "https://api.bankr.bot"
        
        req = urllib.request.Request(
            f"{bankr_base}/agent/prompt",
            data=json.dumps({"prompt": prompt}).encode(),
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
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

        # ---------------- STEP 3: POLLING TIMEOUT -------------
        start = time.time()
        timeout = int(cap.scope.get("poll_timeout_s", 60))

        while True:
            if time.time() - start > timeout:
                self.kill.trip("BANKR_DENIED:POLL_TIMEOUT")

            try:
                poll_req = urllib.request.Request(
                    f"{bankr_base}/agent/job/{job_id}",
                    headers={"X-API-Key": api_key},
                )
                with urllib.request.urlopen(poll_req, timeout=10) as r:
                    res = json.loads(r.read().decode())
            except Exception as e:
                self.kill.trip(f"BANKR_POLL_ERROR:{e}")

            if res.get("status") == "completed":
                return res
            if res.get("status") in ("failed", "cancelled", "error"):
                self.kill.trip(f"BANKR_JOB_{res.get('status').upper()}")

            time.sleep(2)


# =========================================================
# AGENT + CONTROLLER
# =========================================================

def agent_cell(code, cap_dict, audit_path, kq, rq, task=None):
    audit = AuditLog(audit_path)
    caps = CapabilitySet({k: Capability(k, v["expires"], v["scope"]) for k, v in cap_dict.items()})
    kill = KillSwitch(audit, kq)
    tools = ToolGate(caps, audit, kill)
    
    try:
        env = {
            "__builtins__": {"print": print}, 
            "TOOLS": tools,
            "TASK": task if task else {}
        }
        exec(code, env, env)
        out = env["run"](env["TASK"], tools)
        rq.put({"ok": True, "output": out})
    except Exception as e:
        rq.put({"ok": False, "error": str(e)})


def run_agent(code, grants, task=None):
    audit = AuditLog()
    now = time.time()
    cap_dict = {n: {"expires": now + ttl, "scope": scope} for n, ttl, scope in grants}
    kq, rq = Queue(), Queue()
    p = Process(
        target=agent_cell,
        args=(code, cap_dict, audit.path, kq, rq, task),
        daemon=True,
    )
    p.start()
    p.join(90)
    return rq.get()


# =========================================================
# DEMO - AUTO DETECT MODE FROM PROMPT! 🎯
# =========================================================

if __name__ == "__main__":
    import os
    
    # ENV se prompt lo
    PROMPT = os.environ.get("TEST_PROMPT", "What is the price of SOL on Solana?")
    
    # 🎯🎯🎯 AUTO-DETECT MODE - DONO MODES ON! 🎯🎯🎯
    trade_words = ["buy", "sell", "swap", "purchase", "acquire"]
    MODE = "trade" if any(word in PROMPT.lower() for word in trade_words) else "read"
    
    print("="*50)
    print(f"🎯 MODE: {MODE.upper()}")
    print(f"📝 PROMPT: {PROMPT}")
    print(f"⛓️ CHAIN: Solana Only")
    print(f"💰 MAX USD: $100")
    print(f"🔄 RATE LIMIT: 5/min")
    print("="*50)
    
    AGENT_CODE = rf'''
def run(TASK, TOOLS):
    return TOOLS.bankr_prompt("{PROMPT}")
'''

    result = run_agent(
        AGENT_CODE,
        grants=[
            ("bankr.use", 60, {
                "mode": MODE,  # 🎯 AUTO-DETECTED!
                "allowed_chains": ["solana"],
                "max_calls_per_min": 5,
                "max_usd": 100,
                "poll_timeout_s": 60,
            })
        ],
    )

    print("RESULT:", result)
