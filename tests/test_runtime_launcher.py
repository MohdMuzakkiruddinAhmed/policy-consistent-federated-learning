"""Local trust-material and port checks; no Flower or cloud processes are started."""

import importlib.util
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runtime_launcher_for_tests", ROOT / "scripts/run_flower.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class RuntimePortTests(unittest.TestCase):
    def test_learning_child_environment_excludes_account_secrets_and_python_home(self):
        host = {"PATH": "test-bin", "SystemRoot": "test-windows", "TEMP": "test-temp",
                "AWS_ACCESS_KEY_ID": "dummy-access", "AWS_SECRET_ACCESS_KEY": "dummy-secret",
                "AWS_SESSION_TOKEN": "dummy-session", "AWS_PROFILE": "dummy-profile",
                "AWS_WEB_IDENTITY_TOKEN_FILE": "dummy-token-file", "OPENAI_API_KEY": "dummy-api",
                "PASSWORD": "dummy-password", "PYTHONHOME": "dummy-python-home",
                "PYTHONPATH": "dummy-module-injection", "UNEXPECTED_SECRET": "dummy-future-secret"}
        original = dict(host)
        child = launcher.runtime_environment(host)
        self.assertEqual(child, {"PATH": "test-bin", "SystemRoot": "test-windows", "TEMP": "test-temp"})
        self.assertEqual(host, original)

    def test_ephemeral_ports_are_unique_loopback_ports_and_released(self):
        ports = launcher.reserve_ports(12)
        self.assertEqual(len(ports), len(set(ports)))
        self.assertTrue(all(type(port) is int and 0 < port < 65536 for port in ports))
        held = []
        try:
            for port in ports:
                sock = socket.socket()
                sock.bind(("127.0.0.1", port))
                held.append(sock)
        finally:
            for sock in held:
                sock.close()


@unittest.skipUnless(CRYPTO_AVAILABLE, "Install runtime cryptography for TLS/key checks")
class RuntimeIdentityTests(unittest.TestCase):
    def test_node_keys_are_unique_matching_open_ssh_nist_ec_pairs(self):
        with tempfile.TemporaryDirectory() as directory:
            material = launcher.create_identity_files(Path(directory))
            self.assertEqual(set(material["nodes"]), {f"org_{i:02d}" for i in range(1, 9)} | {"unregistered-probe"})
            public_points = []
            for identity in material["nodes"].values():
                private_bytes = identity["private"].read_bytes()
                self.assertTrue(private_bytes.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"))
                private = serialization.load_ssh_private_key(private_bytes, password=None)
                public = serialization.load_ssh_public_key(identity["public"].read_bytes())
                self.assertIsInstance(private, ec.EllipticCurvePrivateKey)
                self.assertIsInstance(private.curve, ec.SECP384R1)
                self.assertEqual(private.public_key().public_numbers(), public.public_numbers())
                public_points.append((public.public_numbers().x, public.public_numbers().y))
            self.assertEqual(len(public_points), len(set(public_points)))

    def test_ca_server_constraints_and_localhost_sans(self):
        with tempfile.TemporaryDirectory() as directory:
            material = launcher.create_identity_files(Path(directory))
            ca = x509.load_pem_x509_certificate(material["ca"].read_bytes())
            server = x509.load_pem_x509_certificate(material["server"].read_bytes())
            self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertFalse(server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(server.issuer, ca.subject)
            server.verify_directly_issued_by(ca)
            names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertIn("localhost", names.get_values_for_type(x509.DNSName))
            self.assertIn("127.0.0.1", [str(value) for value in names.get_values_for_type(x509.IPAddress)])
            private = serialization.load_pem_private_key(material["server_key"].read_bytes(), password=None)
            self.assertEqual(private.public_key().public_numbers(), server.public_key().public_numbers())

    def test_actual_loopback_tls_trusts_own_ca_and_rejects_unrelated_ca(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            material = launcher.create_identity_files(directory / "expected")
            unrelated = launcher.create_identity_files(directory / "unrelated")
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(material["server"], material["server_key"])
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            listener.settimeout(3)
            port = listener.getsockname()[1]
            observed = []
            errors = []
            def serve():
                try:
                    for _ in range(2):
                        connection, _ = listener.accept()
                        connection.settimeout(3)
                        try:
                            with server_context.wrap_socket(connection, server_side=True) as secure:
                                observed.append("trusted")
                                if secure.recv(1) != b"x":
                                    raise ValueError("unexpected_test_probe")
                                secure.sendall(b"ok")
                        except (ssl.SSLError, ConnectionResetError):
                            connection.close()
                            observed.append("rejected")
                except Exception as error:
                    errors.append(type(error).__name__)
                finally:
                    listener.close()
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                trusted = ssl.create_default_context(cafile=str(material["ca"]))
                with trusted.wrap_socket(socket.socket(), server_hostname="localhost") as connection:
                    connection.settimeout(3)
                    connection.connect(("127.0.0.1", port))
                    self.assertTrue(connection.getpeercert())
                    connection.sendall(b"x")
                    self.assertEqual(connection.recv(2), b"ok")
                wrong_ca = ssl.create_default_context(cafile=str(unrelated["ca"]))
                with self.assertRaises(ssl.SSLCertVerificationError):
                    with wrong_ca.wrap_socket(socket.socket(), server_hostname="localhost") as connection:
                        connection.settimeout(3)
                        connection.connect(("127.0.0.1", port))
            finally:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(observed, ["trusted", "rejected"])


if __name__ == "__main__":
    unittest.main()
