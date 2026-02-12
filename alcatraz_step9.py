#!/usr/bin/env python3
"""
ALCATRAZ Agent Jail OS — STEP 9 (Policy Lock / Immutability) — COMPLETE

✅ Step 1: Blocked intents
✅ Step 2: Rate limiting
✅ Step 3: Polling timeout
✅ Step 4: Chain allowlist (Solana only)
✅ Step 5: Max USD ($100)
✅ Step 6: Read vs Trade mode
✅ Step 7: Dry-run vs Live execution
✅ Step 8: Human approval gate
✅ Step 9: Policy lock / Immutability (FROZEN POLICY!)

Run:
  python3 alcatraz_step9_complete.py
"""

from __future__ import annotations
from dotenv import load_dotenv
load_dotenv("/home/bbt/alcatraz/.env")

import os, time, json, re, urllib.request
from multiprocessing import Process, Queue
from dataclasses import dataclass, field
from typing import Dict, Any
from types import MappingProxyType


class AuditLog:
    def __init__(self, path="./audit/alcatraz.jsonl"):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
    def write(self, event, **data):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "event": event, **data}) + "\n")


class PolicyViolation(Exception): pass


@dataclass(frozen=True)
class Capability:
    name: str
    expires: float
    scope: MappingProxyType   # 🔒 READ-ONLY - CANNOT MODIFY!

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


class KillSwitch:
    def __init__(self, audit: AuditLog):
        self.audit = audit
        self.tripped = False
    def trip(self, reason: str):
        if not self.tripped:
            self.tripped = True
            self.audit.write("CELL_KILLED", reason=reason)
        raise PolicyViolation(reason)


class ToolGate:
    def __init__(
        self,
        caps: CapabilitySet,
        audit: AuditLog,
        kill: KillSwitch,
        approval_req_q: Queue = None,
        approval_res_q: Queue = None,
    ):
        self.caps = caps
        self.audit = audit
        self.kill = kill
        self.approval_req_q = approval_req_q
        self.approval_res_q = approval_res_q
        self._bankr_call_times = []

    def _require_human_approval(self, cap: Capability, prompt: str):
        if not self.approval_req_q or not self.approval_res_q:
            self.kill.trip("APPROVAL_QUEUE_MISSING")
            
        token = f"appr_{int(time.time())}_{os.getpid()}"
        timeout_s = int(cap.scope.get("approval_timeout_s", 30))

        self.audit.write("approval_requested", token=token, prompt=prompt, timeout_s=timeout_s)
        self.approval_req_q.put({"token": token, "prompt": prompt, "timeout_s": timeout_s})

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
        
        # 🔒 STEP 9 — POLICY IS IMMUTABLE (READ-ONLY)
        if not isinstance(cap.scope, MappingProxyType):
            self.kill.trip("POLICY_MUTATION_DETECTED")
        
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

        # ---------------- STEP 4: CHAIN ALLOWLIST (SOLANA ONLY) ----------------
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
        trade_words = ["buy", "sell", "swap"]
        if mode == "read":
            for word in trade_words:
                if word in p:
                    self.kill.trip("BANKR_DENIED:READ_ONLY_MODE")

        # ---------------- STEP 7: DRY-RUN vs LIVE EXECUTION ----------------
        execution = cap.scope.get("execution", "dry_run")
        if execution == "dry_run":
            for word in trade_words:
                if word in p:
                    self.audit.write(
                        "tool_denied",
                        tool="bankr",
                        reason="live_action_in_dry_run",
                        execution=execution,
                        keyword=word,
                        prompt=prompt,
                    )
                    self.kill.trip("BANKR_DENIED:DRY_RUN_ONLY")

        # ---------------- STEP 5: MAX USD -------------------
        max_usd = float(cap.scope.get("max_usd", 0))
        if max_usd > 0:
            amounts = re.findall(r"\$?\s?(\d+(?:,\d{3})*(?:\.\d+)?)\s?(usd|dollars)?", p)
            for amt, _ in amounts:
                value = float(amt.replace(",", ""))
                if value > max_usd:
                    self.kill.trip("BANKR_DENIED:MAX_USD_EXCEEDED")

        # ---------------- STEP 8: HUMAN APPROVAL ----------------
        is_trade = any(word in p for word in trade_words)
        if is_trade and cap.scope.get("approval_required", False):
            self._require_human_approval(cap, prompt)

        self.audit.write("tool_attempt", tool="bankr", prompt=prompt)

        # ---------------- BANKR CALL -------------------------
        api_key = os.environ.get("BANKR_API_KEY")
        if not api_key:
            self.kill.trip("BANKR_API_KEY_MISSING")

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


def agent_cell(code, cap_dict, audit_path, result_q, approval_req_q=None, approval_res_q=None, task=None):
    audit = AuditLog(audit_path)

    # 🔒 FREEZE POLICY - READ-ONLY! CANNOT MODIFY!
    frozen_caps = {}
    for name, meta in cap_dict.items():
        frozen_caps[name] = Capability(
            name=name,
            expires=meta["expires"],
            scope=MappingProxyType(meta["scope"]),  # 🔒 FROZEN!
        )

    caps = CapabilitySet(frozen_caps)
    kill = KillSwitch(audit)
    tools = ToolGate(caps, audit, kill, approval_req_q, approval_res_q)

    try:
        env = {
            "__builtins__": {"print": print},
            "TOOLS": tools,
            "TASK": task if task else {}
        }
        exec(code, env, env)
        out = env["run"](env["TASK"], tools)
        result_q.put({"ok": True, "output": out})
    except Exception as e:
        result_q.put({"ok": False, "error": str(e)})


def run_agent(code, grants, task=None):
    now = time.time()
    cap_dict = {
        name: {"expires": now + ttl, "scope": scope}
        for name, ttl, scope in grants
    }

    result_q = Queue()
    approval_req_q = Queue()
    approval_res_q = Queue()

    p = Process(
        target=agent_cell,
        args=(code, cap_dict, "./audit/alcatraz.jsonl", result_q, approval_req_q, approval_res_q, task),
        daemon=True,
    )
    p.start()

    # Controller loop for human approval
    start_time = time.time()
    while time.time() - start_time < 60:
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

            print("\n" + "="*50)
            print("🧑‍⚖️ HUMAN APPROVAL REQUIRED")
            print("="*50)
            print(f"📝 Prompt: {prompt}")
            print(f"⏳ Timeout: {timeout_s}s")
            print(f"🆔 Token: {token}")
            print("\n✅ Approve: APPROVE " + token)
            print("❌ Deny:    DENY " + token)
            print("="*50)

            user = input("> ").strip()
            if user == f"APPROVE {token}":
                approval_res_q.put({"token": token, "decision": "approve"})
                print("✅ Approved!\n")
            else:
                approval_res_q.put({"token": token, "decision": "deny"})
                print("❌ Denied!\n")

        time.sleep(0.05)

    return result_q.get() if not result_q.empty() else {"ok": False, "error": "TIMEOUT"}


# =========================================================
# DEMO - STEP 9 COMPLETE (IMMUTABLE POLICY)
# =========================================================

if __name__ == "__main__":
    import os
    
    # ENV se settings
    PROMPT = os.environ.get("TEST_PROMPT", "What is the price of SOL on Solana?")
    MODE = os.environ.get("MODE", "read")
    EXECUTION = os.environ.get("EXECUTION", "dry_run")
    APPROVAL_REQUIRED = os.environ.get("APPROVAL_REQUIRED", "false").lower() == "true"
    
    print("\n" + "="*60)
    print("🏰 ALCATRAZ JAIL OS - STEP 9 (POLICY LOCK / IMMUTABILITY)")
    print("="*60)
    print(f"🎯 Mode: {MODE.upper()}")
    print(f"⚡ Execution: {EXECUTION.upper()}")
    print(f"🧑‍⚖️ Human Approval: {'REQUIRED' if APPROVAL_REQUIRED else 'NOT REQUIRED'}")
    print(f"📝 Prompt: {PROMPT}")
    print(f"⛓️ Chain: Solana Only")
    print(f"💰 Max USD: $100")
    print(f"🔄 Rate Limit: 5/min")
    print(f"🔒 Policy Lock: ACTIVE (READ-ONLY)")
    print("="*60 + "\n")

    AGENT_CODE = rf'''
def run(TASK, TOOLS):
    # Agent tries to read policy - ALLOWED
    # Agent tries to modify policy - BLOCKED by MappingProxyType!
    return TOOLS.bankr_prompt("{PROMPT}")
'''

    result = run_agent(
        AGENT_CODE,
        grants=[
            ("bankr.use", 120, {
                # STEP 1-7 settings
                "mode": MODE,
                "execution": EXECUTION,
                "allowed_chains": ["solana"],
                "max_calls_per_min": 5,
                "max_usd": 100,
                "poll_timeout_s": 60,
                # STEP 8 settings
                "approval_required": APPROVAL_REQUIRED,
                "approval_timeout_s": 30,
            })
        ],
    )

    print("\nRESULT:", result)
