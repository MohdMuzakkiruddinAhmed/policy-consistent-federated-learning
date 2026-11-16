"""Verify the local Linux image and record its exact source snapshot; no AWS."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CODE = """
import hashlib,json,os,pathlib,platform,flwr,torch,numpy,sklearn,boto3,sqlalchemy
import pcfl.flower_app as app
manifest=json.loads(pathlib.Path('/app/containers/build-source.json').read_text())
for name,expected in manifest['files_sha256'].items():
    path=pathlib.Path('/app')/name
    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
        raise RuntimeError('image_input_digest_mismatch')
p=pathlib.Path('/runtime/verification.txt');p.write_text('synthetic-runtime-check')
readonly=False
try:pathlib.Path('/app/unexpected-write').write_text('must fail')
except OSError:readonly=True
import datetime,ipaddress,sqlite3,subprocess,grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from flwr.proto.control_pb2 import RegisterNodeRequest,ListNodesRequest
from flwr.proto.control_pb2_grpc import ControlStub
from flwr.supercore.primitives.asymmetric import public_key_to_bytes
directory=pathlib.Path('/runtime/schema-check');directory.mkdir()
now=datetime.datetime.now(datetime.timezone.utc)
ca_key=ec.generate_private_key(ec.SECP384R1())
ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'PCFL local container verification CA')])
ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
    .not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
    .sign(ca_key,hashes.SHA256()))
key=ec.generate_private_key(ec.SECP384R1())
leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]))
    .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
    .sign(ca_key,hashes.SHA256()))
(directory/'ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
(directory/'server.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
(directory/'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
log=(directory/'superlink.log').open('w')
server=subprocess.Popen(['flower-superlink','--ssl-ca-certfile',str(directory/'ca.crt'),'--ssl-certfile',str(directory/'server.pem'),
    '--ssl-keyfile',str(directory/'server.key'),'--enable-supernode-auth','--database',str(directory/'state.sqlite'),
    '--storage-dir',str(directory/'ffs'),'--serverappio-api-address','127.0.0.1:9091','--fleet-api-address','127.0.0.1:9092',
    '--control-api-address','127.0.0.1:9093'],stdout=log,stderr=subprocess.STDOUT)
try:
    channel=grpc.secure_channel('localhost:9093',grpc.ssl_channel_credentials(root_certificates=(directory/'ca.crt').read_bytes()))
    grpc.channel_ready_future(channel).result(timeout=20)
    stub=ControlStub(channel)
    public=ec.generate_private_key(ec.SECP384R1()).public_key()
    registered=stub.RegisterNode(RegisterNodeRequest(public_key=public_key_to_bytes(public)),timeout=10)
    listed=stub.ListNodes(ListNodesRequest(),timeout=10)
    if registered.node_id<=0 or len(listed.nodes_info)!=1:raise RuntimeError('schema_registration_failed')
    with sqlite3.connect(directory/'state.sqlite') as db:node_count=db.execute('SELECT COUNT(*) FROM node').fetchone()[0]
    if node_count!=1:raise RuntimeError('schema_persistence_failed')
    channel.close()
finally:
    server.terminate()
    try:server.wait(timeout=10)
    except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
    log.close()
print(json.dumps({'python':platform.python_version(),'flwr':flwr.__version__,'torch':torch.__version__,
'numpy':numpy.__version__,'sklearn':sklearn.__version__,'boto3':boto3.__version__,'uid':os.getuid(),
'sqlalchemy':sqlalchemy.__version__,'tls_control_schema_registration_verified':node_count==1,
'cpu_only':torch.version.cuda is None,'runtime_volume_writable':p.is_file(),'root_filesystem_readonly':readonly,
'server_app':type(app.server_app).__name__,'client_app':type(app.client_app).__name__,'source_manifest':manifest}))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="pcfl-runtime:0.1.0")
    args = parser.parse_args()
    def run(arguments):
        return subprocess.run(["docker", *arguments], capture_output=True, text=True, check=True, timeout=60).stdout
    run(["run", "--rm", "--read-only", args.image, "--help"])
    verification = json.loads(run(["run", "--rm", "--read-only", "--entrypoint", "python", args.image, "-c", CODE]))
    expected = {"python": "3.12.10", "flwr": "1.27.0", "torch": "2.9.1+cpu", "numpy": "2.4.3",
                "sklearn": "1.8.0", "boto3": "1.44.2", "sqlalchemy": "2.0.48", "uid": 10001, "cpu_only": True,
                "tls_control_schema_registration_verified": True,
                "runtime_volume_writable": True, "root_filesystem_readonly": True,
                "server_app": "ServerApp", "client_app": "ClientApp"}
    if any(verification.get(key) != value for key, value in expected.items()):
        raise RuntimeError("container_verification_failed")
    hashes = verification["source_manifest"]["files_sha256"]
    matched = all((ROOT / name).is_file() and hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected_hash
                  for name, expected_hash in hashes.items())
    image = json.loads(run(["image", "inspect", args.image]))[0]
    pip_check = run(["run", "--rm", "--read-only", "--entrypoint", "python", args.image, "-m", "pip", "check"]).strip()
    report = {"schema_version": "0.1.0", "verified_at_utc": datetime.now(timezone.utc).isoformat(),
              "kind": "local-linux-cpu-container-build", "successful": matched,
              "local_tag": args.image, "local_image_id": image["Id"], "image_size_bytes": image["Size"],
              "registry_image_pushed": False, "aws_resources_created": False,
              "source_matches_worktree_at_verification": matched, "verification": verification,
              "pip_check": pip_check,
              "limitations": ["Local image, not an ECR digest or AWS deployment",
                              "Integrated cloud DynamoDB/OPA training adapter remains missing",
                              "Rebuild whenever a source snapshot hash differs"]}
    (ROOT / "containers/build_validation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"successful": matched, "local_image_id": image["Id"], "worktree_sources_match": matched,
                      "pip_check": pip_check}, indent=2))
    if not matched:
        raise SystemExit("Source changed after image snapshot; rebuild before release.")


if __name__ == "__main__":
    main()
