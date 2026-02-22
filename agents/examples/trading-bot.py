#!/usr/bin/env python3
"""
Trading Bot with PiQrypt Audit Trail

Demonstrates how a trading bot can use PiQrypt to create
an immutable audit trail for SEC/FINRA compliance.

Usage:
    python trading-bot.py
"""

import time
import piqrypt as aiss


class TradingBot:
    """Autonomous trading bot with PiQrypt audit trail."""
    
    def __init__(self, name="trading_bot_v1"):
        """Initialize bot with PiQrypt identity."""
        # Generate cryptographic identity
        self.private_key, self.public_key = aiss.generate_keypair()
        self.agent_id = aiss.derive_agent_id(self.public_key)
        self.name = name
        
        print(f"🤖 Trading Bot initialized")
        print(f"   Agent ID: {self.agent_id}")
        print(f"   Audit trail: ~/.piqrypt/events/")
    
    def analyze_market(self, symbol):
        """Simulate market analysis."""
        # In real bot: use ML model, technical indicators, etc.
        import random
        
        price = random.uniform(100, 200)
        signal = random.choice(["buy", "sell", "hold"])
        confidence = random.uniform(0.6, 0.99)
        
        return {
            "symbol": symbol,
            "price": price,
            "signal": signal,
            "confidence": confidence
        }
    
    def make_decision(self, symbol):
        """
        Make trading decision and sign with PiQrypt.
        
        This creates a cryptographic proof of:
        - What decision was made
        - When it was made
        - By which agent
        - Cannot be modified retroactively
        """
        # Analyze market
        analysis = self.analyze_market(symbol)
        
        # Create decision payload
        decision_payload = {
            "event_type": "trade_decision",
            "symbol": analysis["symbol"],
            "action": analysis["signal"],
            "price": analysis["price"],
            "confidence": analysis["confidence"],
            "model_version": "ml_v2.1",
            "timestamp": time.time()
        }
        
        # Sign decision with PiQrypt
        event = aiss.stamp_event(
            self.private_key,
            self.agent_id,
            payload=decision_payload
        )
        
        # Store in audit trail
        aiss.store_event(event)
        
        print(f"✓ Decision signed: {analysis['signal']} {symbol} @ ${analysis['price']:.2f}")
        print(f"  Confidence: {analysis['confidence']:.2%}")
        print(f"  Event hash: {aiss.compute_event_hash(event)[:16]}...")
        
        return event
    
    def execute_trade(self, decision_event):
        """Execute trade and sign execution."""
        # Extract decision
        payload = decision_event["payload"]
        action = payload["action"]
        
        if action == "hold":
            print("  → No trade executed (hold)")
            return None
        
        # Simulate trade execution
        execution_payload = {
            "event_type": "trade_executed",
            "symbol": payload["symbol"],
            "action": action,
            "price": payload["price"],
            "quantity": 100,
            "order_id": f"ORD-{int(time.time())}",
            "decision_hash": aiss.compute_event_hash(decision_event)
        }
        
        # Sign execution
        execution_event = aiss.stamp_event(
            self.private_key,
            self.agent_id,
            payload=execution_payload,
            previous_hash=aiss.compute_event_hash(decision_event)
        )
        
        # Store
        aiss.store_event(execution_event)
        
        print(f"  → Trade executed: {execution_payload['order_id']}")
        
        return execution_event
    
    def export_audit_trail(self, output_path="audit.json"):
        """Export audit trail for regulators."""
        print(f"\n📋 Exporting audit trail to {output_path}...")
        
        # Load all events
        events = aiss.load_events()
        
        # Create identity export
        identity = aiss.export_identity(self.agent_id, self.public_key)
        
        # Export
        audit = aiss.export_audit_chain(identity, events)
        
        import json
        with open(output_path, 'w') as f:
            json.dump(audit, f, indent=2)
        
        print(f"✓ Exported {len(events)} events")
        print(f"  File: {output_path}")
        print(f"  Verifiable by: piqrypt verify chain.json")


def main():
    """Demo trading bot with PiQrypt."""
    print("=" * 60)
    print("Trading Bot with PiQrypt Audit Trail")
    print("=" * 60)
    print()
    
    # Initialize bot
    bot = TradingBot()
    print()
    
    # Make some trading decisions
    symbols = ["AAPL", "GOOGL", "MSFT", "TSLA", "AMZN"]
    
    for symbol in symbols:
        print(f"\n📊 Analyzing {symbol}...")
        decision = bot.make_decision(symbol)
        bot.execute_trade(decision)
        time.sleep(0.5)  # Simulate delay
    
    print()
    
    # Export audit trail
    bot.export_audit_trail("trading-audit.json")
    
    print()
    print("=" * 60)
    print("✅ Demo complete")
    print()
    print("Next steps:")
    print("  1. Verify audit: piqrypt verify trading-audit.json")
    print("  2. Search events: piqrypt search --type trade_executed")
    print("  3. For Pro: piqrypt export --certified (legal compliance)")
    print("=" * 60)


if __name__ == "__main__":
    main()
