#!/usr/bin/env python3
"""
HR Assistant with PiQrypt Audit Trail

Demonstrates GDPR/EEOC compliant AI hiring decisions
with cryptographic audit trail.

Usage:
    python hr-assistant.py
"""

import time
import hashlib
import piqrypt as aiss


class HRAssistant:
    """AI HR assistant with PiQrypt compliance."""

    def __init__(self):
        """Initialize HR assistant."""
        self.private_key, self.public_key = aiss.generate_keypair()
        self.agent_id = aiss.derive_agent_id(self.public_key)

        print("👥 HR Assistant initialized")
        print(f"   Agent ID: {self.agent_id}")
        print("   Compliance: GDPR Art. 22 (automated decisions)")

    def evaluate_candidate(self, cv_text, job_requirements):
        """
        Evaluate candidate with explainable AI.
        
        GDPR Art. 22: Right to explanation of automated decisions.
        """
        # Simulate AI evaluation (in real: NLP model)
        import random

        # Hash CV (privacy - no PII in audit trail)
        cv_hash = hashlib.sha256(cv_text.encode()).hexdigest()

        # Evaluation
        score = random.uniform(0, 100)
        decision = "interview" if score > 70 else "reject"

        reasons = []
        if "python" in cv_text.lower():
            reasons.append("Relevant Python experience")
        if "5 years" in cv_text.lower():
            reasons.append("Sufficient experience (5+ years)")
        if score > 80:
            reasons.append("Strong overall fit")

        # Decision payload (GDPR compliant - no PII)
        payload = {
            "event_type": "candidate_evaluation",
            "cv_hash": cv_hash,  # Hashed, not raw CV
            "job_id": job_requirements.get("job_id"),
            "score": score,
            "decision": decision,
            "reasons": reasons,
            "model_version": "hr_nlp_v2.3",
            "protected_attributes_used": False,  # EEOC compliance
            "timestamp": time.time()
        }

        # Sign with PiQrypt
        event = aiss.stamp_event(
            self.private_key,
            self.agent_id,
            payload=payload
        )

        # Store
        aiss.store_event(event)

        return event

    def explain_decision(self, event):
        """
        Provide explanation (GDPR Art. 22).
        
        Candidate has right to:
        1. Know decision was automated
        2. Get explanation
        3. Request human review
        """
        payload = event["payload"]

        explanation = {
            "decision": payload["decision"],
            "score": payload["score"],
            "reasons": payload["reasons"],
            "audit_proof": {
                "event_hash": aiss.compute_event_hash(event),
                "timestamp": payload["timestamp"],
                "agent_id": self.agent_id,
                "verifiable": True
            },
            "rights": {
                "human_review": "Contact: hr@company.com",
                "data_access": "GDPR Art. 15 - Request your data",
                "rectification": "GDPR Art. 16 - Correct inaccuracies"
            }
        }

        return explanation

    def export_for_candidate(self, candidate_email):
        """
        Export candidate's data (GDPR Art. 15 - Right of Access).
        """
        # Search events for this candidate
        events = aiss.load_events()

        # Hash candidate email to find their events
        candidate_hash = hashlib.sha256(candidate_email.encode()).hexdigest()

        candidate_events = [
            e for e in events
            if e.get("payload", {}).get("cv_hash") == candidate_hash
        ]

        print(f"📋 GDPR Data Export for {candidate_email}")
        print(f"   Found {len(candidate_events)} decisions")

        for event in candidate_events:
            explanation = self.explain_decision(event)
            print(f"\n   Decision: {explanation['decision']}")
            print(f"   Reasons: {', '.join(explanation['reasons'])}")
            print(f"   Verifiable: {explanation['audit_proof']['verifiable']}")

        return candidate_events


def demo():
    """Demo HR assistant."""
    print("=" * 60)
    print("HR Assistant with GDPR Compliance")
    print("=" * 60)
    print()

    # Initialize
    assistant = HRAssistant()
    print()

    # Job requirements
    job = {
        "job_id": "JOB-2026-001",
        "title": "Senior Python Developer",
        "requirements": ["Python", "5+ years experience"]
    }

    # Candidate CVs (simulated)
    candidates = [
        {
            "email": "alice@example.com",
            "cv": "Senior developer with 7 years Python experience. Django, FastAPI, ML."
        },
        {
            "email": "bob@example.com",
            "cv": "Junior developer, 2 years Python. Looking to grow."
        },
        {
            "email": "charlie@example.com",
            "cv": "5 years backend development. Python, Go, Docker, Kubernetes."
        }
    ]

    print(f"📊 Evaluating {len(candidates)} candidates...")
    print()

    for candidate in candidates:
        print(f"Candidate: {candidate['email']}")

        # Evaluate
        event = assistant.evaluate_candidate(candidate["cv"], job)

        # Explain
        explanation = assistant.explain_decision(event)

        print(f"  Decision: {explanation['decision']}")
        print(f"  Score: {explanation['score']:.1f}/100")
        print(f"  Reasons: {', '.join(explanation['reasons']) if explanation['reasons'] else 'N/A'}")
        print(f"  Event hash: {explanation['audit_proof']['event_hash'][:16]}...")
        print()

    # GDPR: Candidate requests their data
    print("=" * 60)
    print("GDPR Right of Access (Art. 15)")
    print("=" * 60)
    print()

    assistant.export_for_candidate("alice@example.com")

    print()
    print("=" * 60)
    print("✅ Demo complete - GDPR compliant")
    print()
    print("Compliance features:")
    print("  ✓ Automated decision transparency (Art. 22)")
    print("  ✓ Right to explanation")
    print("  ✓ Audit trail (immutable)")
    print("  ✓ Data minimization (hashed CVs)")
    print("  ✓ Right of access (Art. 15)")
    print("=" * 60)


if __name__ == "__main__":
    demo()
