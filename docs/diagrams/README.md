# PiQrypt — Diagrams

Visual reference for architecture, protocols, and data flows.
SVG files are added manually; this index tracks what exists and what is planned.

---

## Available diagrams

| File | Description |
|------|-------------|
| `architecture_four_layers.svg` | Four-layer stack: AISS → PiQrypt → Vigil → TrustGate with license mapping |
| `aiss_event_chain.svg` | Hash-linked event chain structure: genesis → signed events → prev_hash links |
| `vrs_scoring.svg` | VRS composite scoring: four weighted components (TSI 35%, TS 20%, A2C 30%, Chain 15%) |
| `trustgate_decision_flow.svg` | TrustGate 10-priority policy engine: evaluation order, six decision outcomes, REQUIRE_HUMAN queue |
| `a2a_handshake.svg` | Agent-to-Agent handshake protocol: identity proposal, response, co-signed confirmation |
| `agent_session_cosign.svg` | AgentSession co-signature flow: N agents, N*(N-1)/2 pairwise handshakes, interaction_hash alignment |
| `pcp_protocol_stack.svg` | PCP positioning analogy: TCP/IP → TLS → OAuth → PCP, with scope of each layer |
| `license_tiers.svg` | Tier comparison: Free / Pro / Startup / Team / Business / Enterprise — features and quotas |
| `vigil_data_flow.svg` | Vigil real-time pipeline: AISS bridge → event ingest → VRS compute → alert → TrustGate push |
| `key_rotation_chain.svg` | Key rotation continuity: agent_id A → rotation attestation → agent_id B, full history traversal |

---

*SVG files are source-controlled assets — edit with Inkscape, Figma, or any SVG editor.*
*Generated renders (PNG/PDF) are not committed — produce on demand for documentation exports.*
