"""Run the isolated mTLS policy-writer actor from a private configuration file."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcfl.governance_service import PolicyWriter, create_policy_server
from pcfl.service_io import sdk_clients


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    ddb, _ = sdk_clients(config["storage"])
    writer = PolicyWriter(ddb, config["table_name"])
    writer.initialize()
    server = create_policy_server(writer, config.get("host", "127.0.0.1"), config["port"],
                                  **config["tls"])
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
