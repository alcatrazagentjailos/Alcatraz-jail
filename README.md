# Alcatraz Agent Jail OS

Alcatraz is a capability-based **Agent Jail OS** designed to safely sandbox autonomous AI agents.

This repository demonstrates how **BankrBot (AI-powered crypto assistant)** can be securely constrained using **system-level enforcement**, instead of relying on prompt trust or alignment.

Alcatraz ensures that agents remain **autonomous but accountable**.

---

## What is jailed in BankrBot?

ALCATRAZ “jails” BankrBot by wrapping every Bankr API call behind a **strict, capability-gated ToolGate**.

The agent is **never trusted by default**.  
All execution power is:
- explicitly granted  
- scope-limited  
- time-bound  
- fully audited  
- immediately revocable  

Below are the **exact controls enforced on BankrBot**, implemented step-by-step from **Step 1 to Step 9**.

---

## Step 1 — Intent / Action Blocking

ALCATRAZ blocks dangerous intents **before the request ever reaches BankrBot**, including:

- transfer / withdraw
- approve
- bridge
- staking or fund-moving commands

If a blocked intent is detected:
- execution is terminated immediately
- violation is logged in the audit trail

---

## Step 2 — Rate Limiting

ALCATRAZ enforces strict rate limits on BankrBot usage:

- maximum calls per minute (e.g. 5/min)
- excess calls are denied instantly

This prevents:
- spam
- runaway loops
- uncontrolled API or cost usage

---

## Step 3 — Polling Control (Timeout Enforcement)

Bankr jobs are asynchronous.  
ALCATRAZ enforces:

- maximum polling duration (e.g. 60 seconds)
- long-running or stuck jobs are terminated

This prevents infinite waiting and hung executions.

---

## Step 4 — Chain Allowlist

ALCATRAZ restricts which blockchains BankrBot can operate on.

Example:
- allowed: `Base`
- denied: Ethereum / BSC / Solana (if not explicitly allowed)

If the prompt requests an unapproved chain:
- execution is denied
- policy violation is logged

This prevents cross-chain misuse.

---

## Step 5 — Value / Spend Limit (Max USD)

ALCATRAZ enforces maximum value exposure inside prompts:

- example: `max_usd = 25` or `100`
- prompts exceeding the allowed value are denied

This limits financial exposure and prevents large unauthorized trades.

---

## Step 6 — Read-Only vs Trade Mode

ALCATRAZ separates **safe read operations** from **execution operations**:

- **read mode:** prices, quotes, market data only
- **trade mode:** buy / sell / swap (if allowed)

If the agent is in read-only mode and a trade intent is detected:
- execution is denied immediately

---

## Step 7 — Dry-Run vs Live Execution

Even when trade mode is enabled, ALCATRAZ enforces execution type:

- **dry_run:** simulation only, no real execution
- **live:** real execution (with additional safeguards)

Dry-run mode allows safe testing without real asset movement.

---

## Step 8 — Human Approval Gate (Human-in-the-Loop)

For high-risk actions, ALCATRAZ requires **explicit human approval**:

- a one-time approval token is generated
- approval must be entered within a strict timeout (e.g. 30 seconds)
- missing or incorrect approval results in denial

This ensures **no autonomous trades happen without human consent**.

---

## Step 9 — Policy Lock / Immutability

Once an agent execution begins, the policy is **frozen**:

- the agent cannot modify its own limits
- no self-upgrading or privilege escalation
- only a full restart can apply a new policy

Any attempt to mutate policy triggers immediate termination.

---

## Summary

ALCATRAZ converts BankrBot from a prompt-trusted agent into a **strictly governed execution system**.

**Autonomous, but accountable.  
Audited, scoped, and revocable execution.**

---

## Security Notes

- `.env` files are never committed
- audit logs are excluded via `.gitignore`
- all enforcement actions are logged in structured JSONL format
