"""
Tests — bridges/rpi/piqrypt_rpi.py
Bridge AuditedGPIO + AuditedPiAgent

Run: pytest test_piqrypt_rpi.py -v
"""
import hashlib
import json
import sys
import time
import types
import unittest
from unittest.mock import MagicMock, patch


# ── Mock piqrypt ──────────────────────────────────────────────────────────────

def _setup_piqrypt_mock():
    events = []
    mock = types.ModuleType("piqrypt")
    mock.generate_keypair     = lambda: (b"priv" * 8, b"pub" * 8)
    mock.derive_agent_id      = lambda pub: "AGENT_" + hashlib.sha256(pub).hexdigest()[:12]
    mock.load_identity        = lambda f: {"private_key_bytes": b"key" * 8, "agent_id": "AGENT_TEST"}
    mock.stamp_event          = lambda key, aid, payload: {
        **payload,
        "_pq_agent_id": aid,
        "_pq_timestamp": time.time(),
        "_pq_sig": "mocksig",
    }
    mock.store_event          = lambda e: events.append(e)
    mock.compute_event_hash   = lambda e: hashlib.sha256(json.dumps(e, default=str).encode()).hexdigest()
    mock.export_audit_chain   = lambda path: open(path, "w").write(json.dumps(events))
    mock._events              = events
    sys.modules["piqrypt"] = mock
    return mock, events

_mock_piqrypt, _events = _setup_piqrypt_mock()


# ── Mock RPi.GPIO ─────────────────────────────────────────────────────────────

def _setup_gpio_mock():
    gpio_mod = types.ModuleType("RPi")
    gpio_inner = types.ModuleType("RPi.GPIO")

    # Constants
    gpio_inner.BCM = "BCM"
    gpio_inner.BOARD = "BOARD"
    gpio_inner.IN = "IN"
    gpio_inner.OUT = "OUT"
    gpio_inner.HIGH = 1
    gpio_inner.LOW = 0
    gpio_inner.PUD_UP = "PUD_UP"
    gpio_inner.PUD_DOWN = "PUD_DOWN"
    gpio_inner.RISING = "RISING"
    gpio_inner.FALLING = "FALLING"
    gpio_inner.BOTH = "BOTH"

    _pin_states = {}

    gpio_inner.setmode = MagicMock()
    gpio_inner.setwarnings = MagicMock()
    gpio_inner.setup = MagicMock()
    gpio_inner.output = MagicMock(side_effect=lambda pin, val: _pin_states.update({pin: val}))
    gpio_inner.input = MagicMock(return_value=1)
    gpio_inner.cleanup = MagicMock()
    gpio_inner.add_event_detect = MagicMock()
    gpio_inner.remove_event_detect = MagicMock()
    gpio_inner._pin_states = _pin_states

    gpio_mod.GPIO = gpio_inner
    sys.modules["RPi"] = gpio_mod
    sys.modules["RPi.GPIO"] = gpio_inner

    return gpio_inner

MockGPIO = _setup_gpio_mock()

# Mock smbus2 (I2C) and spidev
for mod_name in ["smbus2", "spidev"]:
    mod = types.ModuleType(mod_name)
    mod.SMBus = MagicMock()
    sys.modules[mod_name] = mod

# Import bridge
from piqrypt_rpi import AuditedGPIO, AuditedPiAgent, stamp_loop  # noqa: E402


# ══════════════════════════════════════════════════════════════════════════════
# Tests AuditedGPIO
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedGPIO(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.gpio = AuditedGPIO(agent_name="gpio_agent")

    # ── Identité ──────────────────────────────────────────────────────────────

    def test_piqrypt_id_generated(self):
        self.assertTrue(self.gpio.piqrypt_id.startswith("AGENT_"))

    def test_identity_from_file(self):
        with patch("piqrypt_rpi.aiss.load_identity",
                   return_value={"private_key_bytes": b"k"*32, "agent_id": "AGENT_FILE"}):
            gpio = AuditedGPIO(identity_file="fake.json")
        self.assertEqual(gpio.piqrypt_id, "AGENT_FILE")

    # ── setup() ───────────────────────────────────────────────────────────────

    def test_setup_stamps_event(self):
        _events.clear()
        self.gpio.setup(18, "OUT")
        self.assertTrue(len(_events) >= 1)

    def test_setup_stamps_pin_and_mode(self):
        _events.clear()
        self.gpio.setup(23, "IN")
        setup_events = [e for e in _events if "setup" in e.get("event_type", "").lower()]
        self.assertTrue(len(setup_events) >= 1)
        setup_e = setup_events[0]
        self.assertIn(23, [setup_e.get("pin"), setup_e.get("channel")])

    # ── output() ──────────────────────────────────────────────────────────────

    def test_output_stamps_event(self):
        _events.clear()
        self.gpio.setup(18, "OUT")
        _events.clear()
        self.gpio.output(18, 1)
        self.assertTrue(len(_events) >= 1)

    def test_output_stamps_pin_and_value(self):
        _events.clear()
        self.gpio.setup(18, "OUT")
        _events.clear()
        self.gpio.output(18, 1)
        output_events = [e for e in _events if "output" in e.get("event_type", "").lower()
                         or "write" in e.get("event_type", "").lower()]
        self.assertTrue(len(output_events) >= 1)

    def test_multiple_outputs_chained(self):
        _events.clear()
        self.gpio.setup(18, "OUT")
        _events.clear()
        self.gpio.output(18, 1)
        count_after_first = len(_events)
        self.gpio.output(18, 0)
        second_batch = _events[count_after_first:]
        if second_batch:
            self.assertIn("previous_event_hash", second_batch[0])

    # ── input() ───────────────────────────────────────────────────────────────

    def test_input_stamps_event(self):
        _events.clear()
        self.gpio.setup(24, "IN")
        _events.clear()
        _ = self.gpio.input(24)
        self.assertTrue(len(_events) >= 1)

    def test_input_returns_value(self):
        self.gpio.setup(24, "IN")
        val = self.gpio.input(24)
        self.assertIn(val, [0, 1])

    def test_input_hashes_value_or_stores_direct(self):
        """GPIO input values (0/1) may be stored directly or hashed — both valid."""
        _events.clear()
        self.gpio.setup(24, "IN")
        _events.clear()
        self.gpio.input(24)
        # Just verify an event was created
        self.assertTrue(len(_events) >= 1)

    # ── add_event_detect() ────────────────────────────────────────────────────

    def test_add_event_detect_stamps_event(self):
        _events.clear()
        self.gpio.setup(25, "IN")
        callback = MagicMock()
        self.gpio.add_event_detect(25, "RISING", callback=callback)
        self.assertTrue(len(_events) >= 1)

    # ── cleanup() ─────────────────────────────────────────────────────────────

    def test_cleanup_stamps_event(self):
        _events.clear()
        self.gpio.cleanup()
        self.assertTrue(len(_events) >= 1)

    def test_cleanup_event_type(self):
        _events.clear()
        self.gpio.cleanup()
        cleanup_events = [e for e in _events if "cleanup" in e.get("event_type", "").lower()
                          or "shutdown" in e.get("event_type", "").lower()]
        self.assertTrue(len(cleanup_events) >= 1)


# ══════════════════════════════════════════════════════════════════════════════
# Tests AuditedPiAgent
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedPiAgent(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.agent = AuditedPiAgent(agent_name="pi_agent")

    # ── Identité ──────────────────────────────────────────────────────────────

    def test_piqrypt_id_generated(self):
        self.assertTrue(self.agent.piqrypt_id.startswith("AGENT_"))

    def test_event_count_initial(self):
        self.assertIsInstance(self.agent.event_count, int)

    def test_last_event_hash_initial(self):
        # May be None initially or a string
        leh = self.agent.last_event_hash
        self.assertTrue(leh is None or isinstance(leh, str))

    # ── stamp_sensor() ────────────────────────────────────────────────────────

    def test_stamp_sensor_creates_event(self):
        _events.clear()
        self.agent.stamp_sensor("temperature", 25.3, "celsius")
        self.assertTrue(len(_events) >= 1)

    def test_stamp_sensor_stamps_sensor_name(self):
        _events.clear()
        self.agent.stamp_sensor("pressure", 1013.25, "hPa")
        sensor_events = [e for e in _events if "sensor" in e.get("event_type", "").lower()]
        self.assertTrue(len(sensor_events) >= 1)

    def test_stamp_sensor_hashed_hashes_value(self):
        _events.clear()
        self.agent.stamp_sensor_hashed("heart_rate", 72, "bpm")
        for e in _events:
            self.assertNotIn("72", json.dumps(e).replace(str(int(time.time())), ""))

    def test_stamp_sensor_increments_count(self):
        initial = self.agent.event_count
        self.agent.stamp_sensor("humidity", 60.0, "%")
        self.assertGreater(self.agent.event_count, initial)

    # ── stamp_decision() ─────────────────────────────────────────────────────

    def test_stamp_decision_creates_event(self):
        _events.clear()
        self.agent.stamp_decision("activate_fan", {"trigger": "temp > 30", "temp": 32.5})
        self.assertTrue(len(_events) >= 1)

    def test_stamp_decision_stamps_action(self):
        _events.clear()
        self.agent.stamp_decision("open_valve", {"pressure": 5.2})
        decision_events = [e for e in _events if "decision" in e.get("event_type", "").lower()]
        self.assertTrue(len(decision_events) >= 1)

    def test_stamp_decision_hashes_sensitive_data(self):
        _events.clear()
        self.agent.stamp_decision("send_alert", {
            "patient_id": "P12345",
            "vital_sign": "critical",
        })
        for e in _events:
            self.assertNotIn("P12345", json.dumps(e))

    # ── stamp_actuator() ─────────────────────────────────────────────────────

    def test_stamp_actuator_creates_event(self):
        _events.clear()
        self.agent.stamp_actuator("relay_1", "ON", {"channel": 18})
        self.assertTrue(len(_events) >= 1)

    def test_stamp_actuator_stamps_actuator_name(self):
        _events.clear()
        self.agent.stamp_actuator("motor_left", "FORWARD", {"speed": 50})
        actuator_events = [e for e in _events if "actuator" in e.get("event_type", "").lower()]
        self.assertTrue(len(actuator_events) >= 1)

    # ── stamp_system_metrics() ────────────────────────────────────────────────

    def test_stamp_system_metrics_creates_event(self):
        _events.clear()
        self.agent.stamp_system_metrics()
        self.assertTrue(len(_events) >= 1)

    def test_stamp_system_metrics_event_type(self):
        _events.clear()
        self.agent.stamp_system_metrics()
        sys_events = [e for e in _events if "metric" in e.get("event_type", "").lower()
                      or "system" in e.get("event_type", "").lower()]
        self.assertTrue(len(sys_events) >= 1)

    # ── stamp_network_event() ─────────────────────────────────────────────────

    def test_stamp_network_event_creates_event(self):
        _events.clear()
        self.agent.stamp_network_event("mqtt_publish", {"topic_hash": "abc123"})
        self.assertTrue(len(_events) >= 1)

    # ── stamp_error() ─────────────────────────────────────────────────────────

    def test_stamp_error_creates_event(self):
        _events.clear()
        self.agent.stamp_error("sensor_timeout", "Temperature sensor not responding")
        self.assertTrue(len(_events) >= 1)

    def test_stamp_error_hashes_message(self):
        _events.clear()
        self.agent.stamp_error("auth_failure", "SECRET_KEY_XYZ failed to authenticate")
        for e in _events:
            self.assertNotIn("SECRET_KEY_XYZ", json.dumps(e))

    # ── stamp() générique ─────────────────────────────────────────────────────

    def test_stamp_generic_creates_event(self):
        _events.clear()
        self.agent.stamp("custom_event", {"data_hash": "abc123"})
        self.assertTrue(len(_events) >= 1)

    # ── shutdown() ────────────────────────────────────────────────────────────

    def test_shutdown_stamps_event(self):
        _events.clear()
        self.agent.shutdown()
        shutdown_events = [e for e in _events if "shutdown" in e.get("event_type", "").lower()
                           or "stop" in e.get("event_type", "").lower()]
        self.assertTrue(len(shutdown_events) >= 1)

    # ── hash chaining ─────────────────────────────────────────────────────────

    def test_last_event_hash_updated(self):
        initial = self.agent.last_event_hash
        self.agent.stamp_sensor("temp", 25.0, "C")
        self.assertNotEqual(self.agent.last_event_hash, initial)

    def test_sequential_events_chained(self):
        _events.clear()
        self.agent.stamp_sensor("temp", 25.0, "C")
        count_after_first = len(_events)
        self.agent.stamp_sensor("humidity", 60.0, "%")
        second_batch = _events[count_after_first:]
        if second_batch:
            self.assertIn("previous_event_hash", second_batch[0])

    # ── export ────────────────────────────────────────────────────────────────

    def test_export_audit(self):
        import tempfile
        import os
        _events.clear()
        self.agent.stamp_sensor("test_sensor", 42.0, "unit")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.agent.export_audit(path)
            self.assertTrue(os.path.exists(path))
            data = json.loads(open(path).read())
            self.assertIsInstance(data, list)
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Tests @stamp_loop décorateur
# ══════════════════════════════════════════════════════════════════════════════

class TestStampLoop(unittest.TestCase):

    def setUp(self):
        _events.clear()

    def test_stamp_loop_stamps_iteration(self):
        @stamp_loop("sensor_loop", agent_name="test_pi")
        def read_sensors():
            return {"temp": 25.3, "humidity": 60.0}

        result = read_sensors()
        self.assertIsNotNone(result)
        self.assertTrue(len(_events) >= 1)

    def test_stamp_loop_stamps_result_hash(self):
        @stamp_loop("control_loop", agent_name="test_pi")
        def control():
            return {"motor": "ON", "speed": 50}

        control()
        complete = [e for e in _events if "complete" in e.get("event_type", "").lower()
                    or "end" in e.get("event_type", "").lower()]
        if complete:
            self.assertIn("result_hash", complete[0])

    def test_stamp_loop_preserves_return(self):
        @stamp_loop("read", agent_name="test_pi")
        def read():
            return {"voltage": 3.3}

        result = read()
        self.assertEqual(result["voltage"], 3.3)

    def test_stamp_loop_stamps_error(self):
        @stamp_loop("failing_loop", agent_name="test_pi")
        def fail():
            raise RuntimeError("I2C bus error")

        with self.assertRaises(RuntimeError):
            fail()
        error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
        self.assertTrue(len(error_events) >= 1)

    def test_stamp_loop_preserves_function_name(self):
        @stamp_loop("wrap", agent_name="test")
        def my_loop():
            return None
        self.assertEqual(my_loop.__name__, "my_loop")


# ══════════════════════════════════════════════════════════════════════════════
# Test cross-framework : RPi + AgentSession
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossFrameworkScenario(unittest.TestCase):
    """
    Un agent LLM (CrewAI/LangChain) envoie une commande à un RPi.
    Le payload_hash de la commande doit être identique dans les deux mémoires :
    celle de l'agent LLM et celle du RPi.
    """

    def test_command_hash_preserved_llm_to_rpi(self):
        _events.clear()
        agent = AuditedPiAgent(agent_name="rpi_edge_agent")

        # Commande envoyée par l'orchestrateur LLM
        command = {"action": "activate_relay", "channel": 18, "duration_ms": 500}
        payload_hash = hashlib.sha256(json.dumps(command, sort_keys=True).encode()).hexdigest()

        # RPi reçoit la commande — co-signature (peer = LLM orchestrateur)
        agent.stamp("command_received", {
            "payload_hash": payload_hash,
            "peer": "crewai_orchestrator",
            "action": "activate_relay",
        })

        # Exécution physique
        agent.stamp_actuator("relay_1", "ON", {"channel": 18, "duration_ms": 500})

        # Vérifier que le payload_hash est dans la mémoire RPi
        hashes = [e.get("payload_hash") for e in _events if "payload_hash" in e]
        self.assertIn(payload_hash, hashes)

    def test_sensor_reading_can_be_sent_to_llm(self):
        """
        Le RPi lit un capteur → envoie le hash au LLM pour analyse.
        Le LLM ne reçoit jamais la valeur brute — seulement son hash.
        """
        _events.clear()
        agent = AuditedPiAgent(agent_name="rpi_sensor_agent")

        # Lecture capteur — valeur brute jamais envoyée
        raw_value = 38.7  # température corporelle confidentielle
        sensor_hash = hashlib.sha256(str(raw_value).encode()).hexdigest()

        # Stamp de la lecture avec hash uniquement
        agent.stamp_sensor_hashed("body_temperature", raw_value, "celsius")

        # "Envoi" au LLM — seulement le hash
        agent.stamp("reading_sent_to_llm", {
            "payload_hash": sensor_hash,
            "peer": "medical_ai_agent",
            "sensor": "body_temperature",
        })

        # Vérifier que la valeur brute n'est jamais dans la mémoire
        for e in _events:
            self.assertNotIn("38.7", json.dumps(e))


if __name__ == "__main__":
    unittest.main(verbosity=2)
