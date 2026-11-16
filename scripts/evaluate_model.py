"""Run a validation-only mTLS evaluator using its own private configuration."""

import argparse
import json
from pathlib import Path
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcfl.evaluation import DynamoManifestResolver, EvaluationService, make_evaluation_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if config.get("dataset_role", "validation") != "validation" or config.get("confirmatory", False) is not False:
        raise ValueError("this_evaluator_supports_validation_only")
    metadata = config["model_metadata"]
    if isinstance(metadata, str):
        metadata = json.loads(Path(metadata).read_text(encoding="utf-8"))
    clients = {}
    aws = config.get("aws")
    if aws:
        import boto3
        from botocore.config import Config
        shared = {"region_name": aws["region"], "config": Config(connect_timeout=5, read_timeout=10,
                    retries={"max_attempts": 0})}
        if aws.get("local_emulator"):
            for service in ("dynamodb", "s3"):
                endpoint = aws[f"{service}_endpoint"]
                parsed = urlparse(endpoint)
                if parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.scheme != "http":
                    raise ValueError("local_emulator_endpoint_must_be_loopback")
                options = {**shared, "endpoint_url": endpoint,
                           "aws_access_key_id": aws["local_access_key"], "aws_secret_access_key": aws["local_secret_key"]}
                if service == "s3":
                    options["config"] = Config(s3={"addressing_style": "path"}, connect_timeout=5, read_timeout=10,
                                                retries={"max_attempts": 0})
                clients[service] = boto3.client(service, **options)
        else:
            if any("endpoint" in key or "access_key" in key or "secret_key" in key for key in aws):
                raise ValueError("production_evaluation_uses_role_credentials_and_aws_endpoints")
            account = aws.get("expected_account_id")
            if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
                raise ValueError("production_evaluation_expected_account_required")
            if boto3.client("sts", **shared).get_caller_identity()["Account"] != account:
                raise ValueError("production_evaluation_account_mismatch")
            clients = {service: boto3.client(service, **shared) for service in ("dynamodb", "s3")}
    service = EvaluationService(metadata, config["validation_path"], config["validation_sha256"],
        model_root=config.get("model_root"), max_examples=config.get("max_examples", 512), seed=config.get("seed", 296),
        s3_client=clients.get("s3"), allowed_bucket=aws.get("bucket") if aws else None,
        allowed_prefix=aws.get("model_prefix", "models/candidates/") if aws else "models/candidates/",
        manifest_resolver=DynamoManifestResolver(clients["dynamodb"], aws["table"]) if aws else None)
    tls = config["tls"]
    server = make_evaluation_server(service, (args.host, args.port), certificate=tls["server_cert"],
                                    private_key=tls["server_key"], client_ca=tls["client_ca"])
    print(json.dumps({"ready": True, "https": True, "mutual_tls": True, "port": server.server_port,
                      "dataset_role": "validation"}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
