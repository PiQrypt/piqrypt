# Trust Scoring System — Technical Specification

**Version:** 1.1  
**Date:** 2026-02-21  
**Standard:** AISS v1.1 (Agent Identity and Signature Standard)  
**Status:** Production Ready (v1.6.0 roadmap)

---

## Abstract

As AI agents transition from advisory to operational roles—executing trades, controlling industrial systems, making autonomous decisions—the absence of cryptographic accountability creates systemic risk. The Trust Scoring System provides a **quantitative, auditable, non-discriminatory** metric for evaluating the cryptographic integrity and operational reliability of autonomous agents.

This document defines the mathematical framework, implementation architecture, threat model, and defensive rationale for the Trust Score protocol integrated into PiQrypt v1.6+.

**Key Principle:** Trust Score is an **indicator**, never a gate. It observes, does not judge. It informs, does not block.

---

## Table of Contents

```
1. Introduction & Motivation
2. Threat Landscape — AI as Operational Attack Surface
3. Core Principles
4. Mathematical Framework
5. Metrics Deep Dive
6. Threat Model & Detection Capabilities
7. Implementation Status (v1.5.0 → v1.6.0)
8. CTO Defensibility Matrix
9. Case Study: AI-Driven Malware (February 2026)
10. Limitations & Future Work
11. References
```

---

## 1. Introduction & Motivation

### 1.1 Context

Recent security research (February 2026) demonstrated that AI assistants (Grok, Copilot) can be repurposed as **covert C2 proxies** within malware infrastructure. AI systems are no longer passive tools—they are:

- **Runtime participants** (execute delegated actions)
- **Context-aware processors** (maintain internal state)
- **Network-interacting components** (API calls, data fetches)

**The structural gap:** Traditional security models assume servers have certificates, users authenticate, APIs are logged. But autonomous AI agents:

- ✅ Maintain internal state
- ✅ Perform delegated decisions
- ✅ Interact with external services
- ✅ Trigger real-world actions

Yet they typically **lack:**

- ❌ Persistent cryptographic identity
- ❌ Deterministic continuity proof
- ❌ Signed decision trails
- ❌ Fork detection mechanisms

**Result:** Systemic ambiguity. No standardized way to prove an agent's identity remained stable, its history unmodified, or that it didn't fork into divergent execution paths.

### 1.2 Trust Score Objective

The Trust Score quantifies:

1. **Cryptographic continuity** (Identity → Signature → Chain integrity)
2. **Operational reliability** (Finalization rate, protocol adherence)
3. **Interaction diversity** (Anti-clustering, Sybil resistance)
4. **Verified collaboration** (Cross-agent authentication)

**What it is NOT:**
- ❌ Access control gate (never blocks operations)
- ❌ Reputation system (no human judgment)
- ❌ Proof of correctness (integrity ≠ quality)

**What it IS:**
- ✅ Technical health indicator
- ✅ Cryptographic accountability metric
- ✅ Audit trail quality score
- ✅ Forensic readiness signal

---

## 2. Threat Landscape — AI as Operational Attack Surface

### 2.1 Emerging Attack Vectors

**Traditional threats:**
- Backdoor injection (model poisoning)
- Prompt injection (adversarial inputs)
- Data exfiltration (training data leakage)

**New operational threats (2026):**

1. **AI-as-C2 Relay**
   - Malware uses LLM APIs as command relays
   - Covert channels via natural language
   - Detection evasion through context transformation

2. **Multi-Agent Coordination Exploits**
   - Compromised agent infects network via A2A protocol
   - Fork attacks (parallel histories)
   - Replay attacks (reuse of signed events)

3. **Identity Forgery**
   - Impersonation of trusted agents
   - Hijacked delegation chains
   - Key compromise without detection

### 2.2 Why Trust Score Matters

**Scenario:** Trading bot cluster (100 agents)

- **Without Trust Score:** Compromised agent operates undetected until financial damage
- **With Trust Score:** Anomalies detected early:
  - `I` drops (chain discontinuity)
  - `D` drops (isolated clustering)
  - `F` drops (missed finalization)
  - `V` shifts (unverified interactions spike)

**Not prevention, but detection:** Trust Score provides forensic breadcrumbs.

---

## 3. Core Principles

### 3.1 Impartiality

**The score is algorithmic, not subjective.**

- Computed from cryptographic primitives (signatures, hashes)
- No human judgment in calculation
- Transparent formula (open source)
- Reproducible by independent verifiers

### 3.2 Non-Discrimination

**Interactions with non-PiQrypt agents are not penalized.**

- Included in denominator (total interactions)
- Not subtracted from score
- Reflects reality (heterogeneous ecosystems)

**Example:**
```
Agent A interacts with:
  - 70 PiQrypt agents (verified)
  - 30 non-PiQrypt agents (unverified)

V_t = 70 / 100 = 0.70 (not 0.70 - 0.30 penalty)
```

### 3.3 Non-Blocking

**Trust Score NEVER gates operations.**

- Used for monitoring, alerting, auditing
- Not enforced at runtime
- Operators decide thresholds (if any)

**Rationale:** Avoid creating single point of failure. Trust Score is an input to human/system decision-making, not a replacement.

### 3.4 Composability

**Integrates with existing systems.**

- No protocol changes required
- Optional telemetry endpoint
- Exportable as JSON metric
- Compatible with SIEM, dashboards, compliance tools

---

## 4. Mathematical Framework

### 4.1 Global Formula

```
S = w_I × I + w_V × V_t + w_D × D_t + w_F × F

Where:
  S ∈ [0, 1]  (Trust Score)
  I ∈ [0, 1]  (Integrity Score)
  V_t ∈ [0, 1]  (Verified Interaction Ratio, time-weighted)
  D_t ∈ [0, 1]  (Diversity Factor, time-weighted)
  F ∈ [0, 1]  (Finalization Reliability)
```

### 4.2 Default Weights (v1.1)

| Parameter | Weight | Rationale |
|-----------|--------|-----------|
| **I** | 0.35 | Cryptographic foundation (highest priority) |
| **V_t** | 0.30 | Cross-validation (second priority) |
| **D_t** | 0.20 | Anti-clustering (Sybil resistance) |
| **F** | 0.15 | Operational reliability (observable behavior) |

**Total:** 1.00

**Why these weights?**

1. **I dominates (0.35):** Without cryptographic integrity, other metrics meaningless
2. **V_t high (0.30):** Cross-agent verification is strongest trust signal
3. **D_t moderate (0.20):** Important but not critical for isolated agents
4. **F lower (0.15):** Operational metric, less fundamental than crypto

**Configurable:** Weights adjustable per deployment (e.g., finance may increase `F`, research may increase `D_t`)

### 4.3 Temporal Weighting

**Problem:** Old interactions shouldn't dominate score indefinitely.

**Solution:** Exponential decay on `V_t` and `D_t`

```python
def temporal_weight(event_timestamp, current_time, half_life=30*86400):
    """
    Exponential decay with 30-day half-life (default)
    
    Args:
        event_timestamp: Unix timestamp of event
        current_time: Current Unix timestamp
        half_life: Seconds for weight to halve (default 30 days)
    
    Returns:
        Weight ∈ (0, 1]
    """
    age = current_time - event_timestamp
    return 2 ** (-age / half_life)
```

**Properties:**
- Recent events: weight ≈ 1.0
- 30 days old: weight = 0.5
- 60 days old: weight = 0.25
- 90 days old: weight = 0.125

**Prevents:** Gaming via bulk historical interactions

---

## 5. Metrics Deep Dive

### 5.1 Integrity Score (I)

**Definition:** Cryptographic continuity of agent's chain.

**Components:**

```python
I = (
    hash_chain_valid      × 0.30 +
    no_unresolved_forks   × 0.25 +
    key_rotation_valid    × 0.20 +
    attestation_current   × 0.15 +
    revocation_clean      × 0.10
)
```

**Computation:**

1. **Hash Chain Valid (0.30)**
   ```python
   def verify_chain(events):
       for i, event in enumerate(events[1:], start=1):
           expected = sha256(events[i-1])
           actual = event.previous_event_hash
           if expected != actual:
               return 0.0
       return 1.0
   ```

2. **No Unresolved Forks (0.25)**
   ```python
   def fork_score(chain):
       forks = detect_forks(chain)
       unresolved = [f for f in forks if not f.resolved]
       return 1.0 - min(len(unresolved) / 5, 1.0)  # 5+ forks → 0
   ```

3. **Key Rotation Valid (0.20)**
   ```python
   def rotation_score(chain):
       rotations = [e for e in chain if e.type == "key_rotation"]
       valid = [r for r in rotations if verify_rotation(r)]
       if not rotations:
           return 1.0  # No rotation attempted = OK
       return len(valid) / len(rotations)
   ```

4. **Attestation Current (0.15)**
   ```python
   def attestation_score(identity_doc, current_time):
       if not identity_doc.attestation:
           return 0.5  # Not required, but bonus if present
       age = current_time - identity_doc.attestation.timestamp
       if age > 365*86400:  # 1 year
           return 0.0
       return 1.0 - (age / (365*86400))
   ```

5. **Revocation Clean (0.10)**
   ```python
   def revocation_score(agent_id, revocation_registry):
       if agent_id in revocation_registry:
           return 0.0
       return 1.0
   ```

**Interpretation:**

| I Score | Meaning |
|---------|---------|
| 1.00 | Perfect cryptographic continuity |
| 0.80-0.99 | Minor issues (old attestation, single resolved fork) |
| 0.50-0.79 | Moderate concerns (multiple forks, rotation issues) |
| <0.50 | Severe compromise (chain breaks, revoked key) |

**Limitations:**

⚠️ `I` measures **continuity**, not **integrity of code/hardware**
- Cannot detect: Compromised private key still signing valid chains
- Cannot detect: Backdoor in agent logic
- Cannot detect: Host system compromise

**Complementary defenses required:** HSM, TPM, secure boot, code signing

---

### 5.2 Verified Interaction Ratio (V_t)

**Definition:** Proportion of interactions with cryptographically verified peers, time-weighted.

**Formula:**

```python
def compute_V_t(interactions, current_time):
    numerator = 0
    denominator = 0
    
    for interaction in interactions:
        weight = temporal_weight(interaction.timestamp, current_time)
        denominator += weight
        
        if interaction.peer_verified:  # PiQrypt handshake completed
            numerator += weight
    
    return numerator / denominator if denominator > 0 else 0.0
```

**Properties:**

- **Non-discriminatory:** Unverified interactions reduce ratio but aren't penalized
- **Time-weighted:** Recent verifications matter more
- **Bootstraps gradually:** New agents start V_t ≈ 0, grows with network

**Example:**

```
Agent timeline:
  Day 1: 10 interactions, 0 verified → V_t ≈ 0.0
  Day 30: 100 interactions, 70 verified → V_t ≈ 0.70
  Day 60: 200 interactions, 180 verified → V_t ≈ 0.90 (recent verified dominate)
```

**Attack resistance:**

- **Sybil flooding:** Caught by `D_t` (diversity factor)
- **Replay old verifications:** Temporal decay limits impact

---

### 5.3 Diversity Factor (D_t)

**Definition:** Entropy of interactions, preventing clustering and Sybil attacks.

**Formula:**

```python
def compute_D_t(interactions, current_time, window=30*86400):
    recent = [i for i in interactions 
              if current_time - i.timestamp < window]
    
    if not recent:
        return 1.0  # No recent interactions = no cluster risk
    
    peer_counts = Counter(i.peer_id for i in recent)
    total = len(recent)
    
    # Shannon entropy
    entropy = -sum((count/total) * log2(count/total) 
                   for count in peer_counts.values())
    
    # Normalize to [0, 1]
    max_entropy = log2(len(peer_counts))
    
    return entropy / max_entropy if max_entropy > 0 else 0.0
```

**Interpretation:**

| D_t | Pattern |
|-----|---------|
| 0.9-1.0 | High diversity (many unique peers) |
| 0.5-0.8 | Moderate clustering (some repeat peers) |
| <0.5 | Closed cluster (few unique peers, heavy repetition) |

**Example:**

```
Agent A (30 days):
  - 100 interactions
  - 80 unique peers
  → D_t ≈ 0.95 (high diversity)

Agent B (30 days):
  - 100 interactions
  - 5 unique peers (20 interactions each)
  → D_t ≈ 0.43 (closed cluster, potential Sybil)
```

**Not a penalty:** Low `D_t` doesn't mean malicious, could be:
- Specialized agent (only talks to specific services)
- Early bootstrap phase
- Isolated deployment

**Signal, not gate.**

---

### 5.4 Finalization Reliability (F)

**Definition:** Operational adherence to protocol completion.

**Measured:**

1. **A2A Handshake Completion Rate**
   ```python
   f_handshake = completed_handshakes / initiated_handshakes
   ```

2. **Event Finalization (TSA Timestamp)**
   ```python
   f_finalization = events_with_TSA / events_eligible_for_TSA
   ```

3. **Protocol Deadline Adherence**
   ```python
   f_deadline = events_finalized_on_time / total_events
   ```

**Aggregate:**

```python
F = (f_handshake × 0.40 + 
     f_finalization × 0.35 + 
     f_deadline × 0.25)
```

**Interpretation:**

| F | Meaning |
|---|---------|
| >0.95 | Highly reliable (protocol-compliant) |
| 0.80-0.95 | Reliable with occasional delays |
| 0.50-0.80 | Operational issues (investigate) |
| <0.50 | Severe unreliability (possible failure) |

**Use case:** Distinguish between:
- Healthy agent with network blips (F ≈ 0.90)
- Compromised agent failing to complete protocols (F < 0.60)

---

## 6. Threat Model & Detection Capabilities

### 6.1 Detectable Attacks

| Attack Type | Detection Mechanism | Score Impact |
|-------------|---------------------|--------------|
| **Chain Tampering** | Hash mismatch | `I` → 0 |
| **Fork Attack** | Multiple branches detected | `I` ↓ (0.5-0.8) |
| **Key Compromise** | Rotation signature invalid | `I` ↓ (0.3-0.6) |
| **Sybil Network** | Low entropy in peers | `D_t` → <0.5 |
| **Replay Attack** | Temporal weights decay old events | `V_t` minimal impact |
| **Protocol Non-Compliance** | Missed finalizations | `F` ↓ |
| **Clustering Exploit** | Closed peer group | `D_t` ↓ |

### 6.2 Non-Detectable Attacks

**Trust Score cannot detect:**

- ❌ **Zero-day exploits** in agent code
- ❌ **Host system compromise** (rootkit, hypervisor)
- ❌ **Private key theft** (if used to sign valid chains)
- ❌ **Model poisoning** (backdoor in ML weights)
- ❌ **Prompt injection** (adversarial inputs)
- ❌ **Social engineering** (operator mistakes)

**Why?** Trust Score measures **cryptographic continuity**, not **semantic correctness** or **host security**.

**Required complementary defenses:**
- Code signing / binary attestation
- Secure boot (TPM, TEE)
- Runtime integrity monitoring (eBPF, seccomp)
- Model provenance tracking
- Input validation / sanitization

### 6.3 False Positives / Negatives

**False Positive (Low score, benign agent):**
- New agent (low `V_t`, `D_t` due to bootstrapping)
- Isolated deployment (low `D_t` legitimately)
- Network issues (low `F` due to transient failures)

**Mitigation:** Score threshold adjusted per use case, grace period for new agents

**False Negative (High score, compromised agent):**
- Stolen private key signing valid chains (`I` = 1.0 despite compromise)
- Subtle model poisoning (undetectable at crypto layer)

**Mitigation:** Layered defense (Trust Score + code signing + anomaly detection)

---

## 7. Implementation Status

### 7.1 Current (v1.5.0)

| Component | Status | Module |
|-----------|--------|--------|
| Cryptographic primitives | ✅ Complete | `aiss/crypto/` |
| Hash chain verification | ✅ Complete | `aiss/chain.py` |
| Fork detection | ✅ Complete | `aiss/fork.py` |
| A2A handshake | ✅ Complete | `aiss/a2a.py` |
| Event timestamping | ✅ Complete | `aiss/stamp.py` |
| TSA integration | ✅ Complete | `aiss/rfc3161.py` |

**Trust Score computation:** ❌ Not yet implemented

### 7.2 Roadmap (v1.6.0 — Q2 2026)

**Target:** Trust Score v1.1 production-ready

**Deliverables:**

1. **Core Engine** (`aiss/trust_score.py`)
   - `compute_I()` — Integrity Score
   - `compute_V_t()` — Verified Interaction Ratio
   - `compute_D_t()` — Diversity Factor
   - `compute_F()` — Finalization Reliability
   - `compute_trust_score()` — Aggregate

2. **CLI Integration**
   ```bash
   piqrypt trust-score compute --agent-id AGENT_ID
   piqrypt trust-score history --days 30
   piqrypt trust-score compare AGENT_A AGENT_B
   ```

3. **Dashboard (Pro)**
   - Visual score breakdown (I/V/D/F components)
   - Historical trend graph
   - Peer comparison matrix
   - Anomaly alerts

4. **Export Formats**
   - JSON (machine-readable)
   - CSV (analytics)
   - PDF (compliance reports)

### 7.3 Future (v1.7.0+)

- Adaptive weights (ML-based per vertical: finance, healthcare, etc.)
- Consensus-based trust (multi-observer verification)
- Federated scoring (privacy-preserving aggregation)
- Integration with SIEM (Splunk, ELK, Datadog)

---

## 8. CTO Defensibility Matrix

**Common technical objections & rebuttals:**

| Question | Response |
|----------|----------|
| **"Sybil attack → inflated score?"** | `D_t` entropy metric + temporal windowing limits impact. Coordinated cluster detectable via low diversity. |
| **"Compromised key → score manipulation?"** | `I` measures **continuity**, not **security**. Requires complementary: HSM, revocation monitoring, attestation. |
| **"Why not PageRank / graph algorithms?"** | **Simplicity, auditability, performance.** Complex graphs = opaque, hard to debug, compute-intensive. |
| **"How to bootstrap trust for new agents?"** | `I` = 1.0 if chain valid (immediate). `V_t`, `D_t`, `F` grow gradually. Grace period configurable. |
| **"Does low score block operations?"** | **Never.** Score = indicator only. Operators set thresholds (if any). Avoid single point of failure. |
| **"Post-quantum = trust guarantee?"** | **No.** PQC = cryptographic resilience. Trust = **observable continuity**. Orthogonal concepts. |
| **"Can Trust Score detect model poisoning?"** | **No.** Crypto layer blind to semantic attacks. Requires: model provenance, adversarial testing, anomaly detection. |
| **"False positives in low-trust environments?"** | **Expected.** Threshold tuning per deployment. New agents, isolated systems legitimately score lower initially. |

---

## 9. Case Study: AI-Driven Malware (February 2026)

### 9.1 Attack Overview

**Source:** Security research demonstrated AI assistants (Grok, Copilot) repurposed as C2 relays.

**Mechanism:**
1. Malware embeds API calls to LLM services
2. Commands encoded in natural language prompts
3. Responses decoded to extract instructions
4. Detection evasion via context transformation

**Impact:** AI systems as **operational actors** without accountability.

### 9.2 Trust Score Analysis (Hypothetical)

**If compromised agent had PiQrypt integrated:**

```
Day 0: Agent compromised, begins C2 relay behavior
  ↓
Day 1: Trust Score metrics shift
  - I: Chain continues (no break) → 1.0
  - V_t: Interacts with external LLM (unverified) → drops to 0.60
  - D_t: Repetitive calls to single API → drops to 0.35
  - F: Misses protocol deadlines (busy relaying) → drops to 0.70
  
  Trust Score: 0.35×1.0 + 0.30×0.60 + 0.20×0.35 + 0.15×0.70
             = 0.35 + 0.18 + 0.07 + 0.105
             = 0.705 (↓ from baseline 0.89)
  ↓
Day 3: Anomaly detected (score drop >0.15)
  → Alert triggered
  → Forensic investigation initiated
  → Compromise identified (before financial damage)
```

**Key insight:** Trust Score doesn't **prevent** C2 relay, but provides **early detection signal**.

### 9.3 Broader Implication

**AI-driven misuse → AI-driven accountability**

As AI systems become operational:
- Insurance requires verifiable logs
- Regulators demand auditability
- Enterprises need provable continuity
- Cross-org collaboration requires identity guarantees

**Cryptographic accountability will become foundational.**

The question is **when**, not **if**.

---

## 10. Limitations & Future Work

### 10.1 Current Limitations

**Trust Score v1.1 does NOT:**

- ❌ Guarantee agent **security** (only continuity)
- ❌ Detect **semantic attacks** (model poisoning, prompt injection)
- ❌ Verify **code integrity** (separate concern: code signing)
- ❌ Prove **hardware security** (separate: TPM, TEE)
- ❌ Replace **human judgment** (tool, not oracle)

### 10.2 Research Directions

**Short-term (v1.6-v1.7):**
- Adaptive weight tuning (per vertical)
- Multi-observer consensus scoring
- Integration with anomaly detection (ML-based)

**Medium-term (v2.0):**
- Zero-knowledge proofs (selective disclosure of score components)
- Federated learning for scoring models
- Cross-chain trust attestation (interoperability)

**Long-term:**
- Formal verification of scoring logic (Coq, TLA+)
- Standardization (NIST, ISO working groups)
- Integration with emerging agent frameworks (AutoGPT, LangChain, etc.)

### 10.3 Open Questions

1. **Optimal weight selection:** Empirical study across verticals needed
2. **Temporal decay function:** Linear? Exponential? Logarithmic? Domain-specific?
3. **Threshold calibration:** Industry benchmarks for "good" vs "concerning" scores?
4. **Interoperability:** How to aggregate scores across heterogeneous systems?

---

## 11. References

### Academic

1. **NIST FIPS 186-5** — Digital Signature Standard (DSS)
2. **NIST SP 800-204A** — Building Secure Microservices-based Applications
3. **OWASP Top 10 for LLM Applications** (2023)
4. **"SoK: Security of Machine Learning"** — IEEE S&P 2018
5. **"Adversarial Examples in Machine Learning"** — Goodfellow et al.

### Standards

6. **RFC 8032** — Edwards-Curve Digital Signature Algorithm (EdDSA)
7. **RFC 8785** — JSON Canonicalization Scheme (JCS)
8. **RFC 3161** — Time-Stamp Protocol (TSP)
9. **ISO/IEC 27001:2022** — Information Security Management

### Industry

10. **AISS v1.1** — Agent Identity and Signature Standard (PiQrypt)
11. **"AI-Driven Malware Leveraging Grok and Copilot"** — Feb 2026 Security Research
12. **SOC2 Trust Service Criteria** — AICPA
13. **GDPR Article 22** — Automated Decision-Making

---

## Appendix A: Formula Reference Card

```python
# Trust Score (S)
S = 0.35×I + 0.30×V_t + 0.20×D_t + 0.15×F

# Integrity (I)
I = 0.30×hash_chain + 0.25×no_forks + 0.20×rotation + 
    0.15×attestation + 0.10×revocation

# Verified Interaction Ratio (V_t)
V_t = Σ(verified × temporal_weight) / Σ(total × temporal_weight)

# Diversity (D_t)
D_t = Shannon_entropy(peer_interactions) / max_entropy

# Finalization (F)
F = 0.40×handshake_rate + 0.35×TSA_rate + 0.25×deadline_rate

# Temporal Weight
weight(t) = 2^(-age_days / 30)
```

---

## Appendix B: CLI Examples

```bash
# Compute current trust score
$ piqrypt trust-score compute --agent-id 5Z8nY7KpL9mN3qR4sT6uV8wX
Trust Score: 0.89
  I (Integrity):           1.00 ✅
  V_t (Verified):          0.85 ✅
  D_t (Diversity):         0.78 ⚠️
  F (Finalization):        0.95 ✅

# Historical trend
$ piqrypt trust-score history --days 30
Date         Score    I     V_t   D_t   F
2026-01-23   0.91    1.00  0.88  0.82  0.96
2026-01-30   0.89    1.00  0.85  0.78  0.95
2026-02-06   0.87    0.98  0.83  0.76  0.94
...

# Compare agents
$ piqrypt trust-score compare AGENT_A AGENT_B
Metric       Agent A   Agent B   Δ
Score        0.89      0.72      +0.17
I            1.00      0.85      +0.15
V_t          0.85      0.65      +0.20
D_t          0.78      0.60      +0.18
F            0.95      0.88      +0.07
```

---

**End of Technical Specification**

*For implementation guide, see: QUICK_START.md*  
*For A2A protocol details, see: A2A_GUIDE.md*  
*For certification service, see: CERTIFICATION.md*

---

*Trust Scoring System v1.1 — PiQrypt Reference Implementation*  
*© 2026 PiQrypt Inc. — MIT License*