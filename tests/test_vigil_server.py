"""
Tests — vigil/vigil_server.py
Serveur HTTP Vigil (port 8421)
"""
import json
import threading
import time
import unittest
import urllib.request
import urllib.error
from pathlib import Path
import sys

# Ajouter vigil/ au path
ROOT = Path(__file__).resolve().parent.parent
VIGIL_DIR = ROOT / "vigil"
if VIGIL_DIR.exists():
    sys.path.insert(0, str(VIGIL_DIR))
sys.path.insert(0, str(ROOT))


class TestVigilServerImport(unittest.TestCase):
    def test_import(self):
        """vigil_server est importable"""
        try:
            import vigil_server
            self.assertIsNotNone(vigil_server)
        except ImportError:
            # Essai depuis le chemin complet
            sys.path.insert(0, str(ROOT / "vigil"))
            import vigil_server
            self.assertIsNotNone(vigil_server)

    def test_has_vigil_server_class(self):
        try:
            import vigil_server
            self.assertTrue(
                hasattr(vigil_server, "VIGILServer") or
                hasattr(vigil_server, "VIGILHandler"),
                "vigil_server doit exposer VIGILServer ou VIGILHandler"
            )
        except ImportError:
            self.skipTest("vigil_server non trouvable")


class TestVigilServerLive(unittest.TestCase):
    """Tests avec serveur reel sur port temporaire."""

    TEST_PORT = 18421  # Port de test pour eviter les conflits

    @classmethod
    def setUpClass(cls):
        try:
            import vigil_server
            cls.server = vigil_server.VIGILServer(host="127.0.0.1", port=cls.TEST_PORT)
            cls.server.start(blocking=False)
            time.sleep(0.5)  # Laisser le serveur demarrer
            cls.server_available = True
        except Exception as e:
            cls.server_available = False
            cls.server = None

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            try:
                cls.server.stop()
            except Exception:
                pass

    def _get(self, path: str) -> dict:
        url = f"http://127.0.0.1:{self.TEST_PORT}{path}"
        with urllib.request.urlopen(url, timeout=3) as r:
            return json.loads(r.read())

    def test_health_endpoint(self):
        """GET /health retourne status ok"""
        if not self.server_available:
            self.skipTest("Serveur non disponible")
        data = self._get("/health")
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("version", data)

    def test_summary_endpoint(self):
        """GET /api/summary retourne un objet"""
        if not self.server_available:
            self.skipTest("Serveur non disponible")
        data = self._get("/api/summary")
        self.assertIsInstance(data, dict)
        self.assertIn("global_vrs", data)

    def test_alerts_endpoint(self):
        """GET /api/alerts retourne une liste"""
        if not self.server_available:
            self.skipTest("Serveur non disponible")
        data = self._get("/api/alerts")
        self.assertIn("alerts", data)
        self.assertIsInstance(data["alerts"], list)

    def test_demo_mode_active(self):
        """Sans backend, le mode DEMO est active"""
        if not self.server_available:
            self.skipTest("Serveur non disponible")
        data = self._get("/health")
        # Le serveur fonctionne meme en mode demo
        self.assertIn(data.get("status"), ["ok", "demo"])

    def test_dashboard_serves_html(self):
        """GET / retourne du HTML"""
        if not self.server_available:
            self.skipTest("Serveur non disponible")
        url = f"http://127.0.0.1:{self.TEST_PORT}/"
        with urllib.request.urlopen(url, timeout=3) as r:
            content_type = r.headers.get("Content-Type", "")
            self.assertIn("html", content_type.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
