"""Explicit SDK endpoints and ephemeral mTLS identities for integration services."""

from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import re
from urllib.parse import urlparse


def sdk_clients(config):
    import boto3
    from botocore.config import Config
    region = config.get("region", "us-east-1")
    common = {"region_name": region}
    tuning = {"connect_timeout": 3, "read_timeout": 5, "retries": {"max_attempts": 0},
              "ignore_configured_endpoint_urls": True}
    if config.get("local_emulation") is True:
        endpoints = [config.get("dynamodb_endpoint"), config.get("s3_endpoint")]
        for service, endpoint in zip(("dynamodb", "s3"), endpoints, strict=True):
            value = urlparse(endpoint or "")
            allowed = {"127.0.0.1", "localhost", "::1"}
            if config.get("isolated_container_emulation") is True:
                allowed.add({"dynamodb": "pcfl-dynamodb", "s3": "pcfl-s3"}[service])
            if (value.scheme != "http" or value.hostname not in allowed
                    or not value.port or value.username or value.password or value.query or value.fragment
                    or value.path not in ("", "/") or value.params):
                raise ValueError("explicit_loopback_emulator_endpoints_required")
        # Fixed test-only credentials never fall through to real account credentials.
        common.update(aws_access_key_id="pcfllocal", aws_secret_access_key="pcfl-local-test-only")
    else:
        if config.get("isolated_container_emulation"):
            raise ValueError("container_emulation_requires_explicit_test_mode")
        if any(config.get(key) for key in ("dynamodb_endpoint", "s3_endpoint", "access_key", "secret_key")):
            raise ValueError("production_endpoint_or_static_credential_override_forbidden")
        expected = config.get("expected_account_id", "")
        if not re.fullmatch(r"[0-9]{12}", expected):
            raise ValueError("explicit_expected_aws_account_required")
        actual = boto3.client("sts", **common, config=Config(**tuning)).get_caller_identity()["Account"]
        if actual != expected:
            raise ValueError("aws_account_mismatch")
    ddb = boto3.client("dynamodb", **common, endpoint_url=config.get("dynamodb_endpoint"), config=Config(**tuning))
    s3 = boto3.client("s3", **common, endpoint_url=config.get("s3_endpoint"),
                      config=Config(**tuning, s3={"addressing_style": "path"}))
    return ddb, s3


def service_identities(directory, *, dns_names=None, additional_servers=(), additional_clients=()):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PCFL integration service CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA384()))
    ca_path = directory / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    identities = {"ca": str(ca_path)}
    names = ("governance", "evaluation", "coordinator", "policy-operator", *additional_servers, *additional_clients)
    if len(set(names)) != len(names) or any(not re.fullmatch(r"[a-z][a-z0-9-]{0,40}", name) for name in names):
        raise ValueError("invalid_service_identity_names")
    for name in names:
        key = ec.generate_private_key(ec.SECP384R1())
        builder = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"pcfl-{name}")]))
            .issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True))
        server = name in {"governance", "evaluation", *additional_servers}
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        if server:
            hosts = ["localhost", *(dns_names or {}).get(name, [])]
            if any(not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host) for host in hosts):
                raise ValueError("invalid_service_dns_name")
            builder = builder.add_extension(x509.SubjectAlternativeName([
                *[x509.DNSName(host) for host in dict.fromkeys(hosts)],
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        certificate = builder.sign(ca_key, hashes.SHA384())
        cert_path, key_path = directory / f"{name}.pem", directory / f"{name}.key"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        identities[name] = {"cert": str(cert_path), "key": str(key_path)}
    return identities
