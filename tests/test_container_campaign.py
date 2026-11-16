"""Ownership/isolation failure tests; full Linux campaign is a separate CLI."""

from pathlib import Path
import io
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_container_campaign import LABEL, ORGANIZATIONS, PrivateCampaign, sha


class ContainerCampaignTests(unittest.TestCase):
    def campaign(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return PrivateCampaign(Path(temporary.name) / "owned", "sha256:test")

    def records(self, campaign):
        result = []
        for index, role in enumerate([*ORGANIZATIONS, "coordinator", "governance", "evaluation", "opa"], 1):
            result.append({"name": role, "role": role, "container_id": "id-" + role,
                "network_ips": {campaign.network: f"172.31.0.{index}"}, "published_ports": {}, "read_only_root": True,
                "mounts": [{"type": "volume", "destination": "/runtime", "volume_name": "volume-" + role}]})
        return result

    def test_distinct_actor_namespaces_and_no_host_clinical_mounts(self):
        campaign = self.campaign()
        campaign.records.extend(self.records(campaign))
        campaign.verify_actor_isolation()
        self.assertEqual(campaign.report["actor_isolation"]["distinct_runtime_volumes"], 12)
        self.assertFalse(campaign.report["actor_isolation"]["S3_role_authorization_enforced"])

    def test_shared_evaluator_volume_or_published_actor_port_fails(self):
        campaign = self.campaign()
        campaign.records.extend(self.records(campaign))
        campaign.records[8]["mounts"] = campaign.records[10]["mounts"]
        with self.assertRaisesRegex(ValueError, "isolation_failed"):
            campaign.verify_actor_isolation()
        campaign.records[:] = self.records(campaign)
        campaign.records[8]["published_ports"] = {"9092/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9092"}]}
        with self.assertRaisesRegex(ValueError, "isolation_failed"):
            campaign.verify_actor_isolation()

    def test_cleanup_refuses_other_container_and_volume_labels(self):
        campaign = self.campaign()
        campaign.containers = ["foreign-container"]
        campaign.volumes = ["foreign-volume"]
        campaign.inspect = Mock(return_value={"Config": {"Labels": {LABEL: "someone-else"}}})
        def docker(*args, **kwargs):
            if args[:2] == ("volume", "ls"):
                return "foreign-volume"
            if args[:2] == ("volume", "inspect"):
                return '[{"Labels":{"' + LABEL + '":"someone-else"}}]'
            if args[:2] == ("ps", "-a"):
                return "foreign-container"
            if args[0] in {"rm", "prune"} or args[:2] == ("volume", "rm"):
                self.fail("Attempted destructive cleanup of foreign resources")
            return ""
        campaign.docker = Mock(side_effect=docker)
        campaign.stop()
        self.assertFalse(campaign.report["cleanup"]["all_owned_containers_removed"])
        self.assertEqual(len(campaign.report["cleanup"]["errors"]), 2)
        self.assertFalse(campaign.report["successful"])

    def test_owned_cleanup_removes_anonymous_and_named_volumes_without_prune(self):
        campaign = self.campaign()
        campaign.containers = ["owned-container"]
        campaign.volumes = ["owned-named-volume", "owned-anonymous-volume"]
        campaign.inspect = Mock(return_value={"Config": {"Labels": {LABEL: campaign.identifier}},
            "State": {"Status": "exited", "ExitCode": 0}, "NetworkSettings": {"Networks": {}}})
        remaining = {"owned-named-volume", "owned-anonymous-volume"}
        def docker(*args, **kwargs):
            if args[0] == "logs":
                return "safe log"
            if args[0] == "rm":
                self.assertEqual(args, ("rm", "-f", "-v", "owned-container"))
                remaining.remove("owned-anonymous-volume")
            elif args[:2] == ("volume", "ls"):
                return "\n".join(sorted(remaining | {"unrelated-volume"}))
            elif args[:2] == ("volume", "inspect"):
                return '[{"Labels":{"' + LABEL + '":"' + campaign.identifier + '"}}]'
            elif args[:2] == ("volume", "rm"):
                self.assertEqual(args[2], "owned-named-volume")
                remaining.remove(args[2])
            elif args[:2] == ("ps", "-a"):
                return "exaiops-lab-control-plane"
            elif "prune" in args:
                self.fail("Global prune must never be used")
            return ""
        campaign.docker = Mock(side_effect=docker)
        campaign.stop()
        self.assertTrue(campaign.report["cleanup"]["all_owned_containers_removed"])
        self.assertTrue(campaign.report["cleanup"]["all_owned_volumes_removed"])
        self.assertFalse(remaining)
        self.assertEqual(campaign.report["cleanup"]["errors"], [])

    def test_host_exports_use_short_names_but_bind_full_immutable_digest(self):
        campaign = self.campaign()
        content = b"immutable model bytes"
        artifact = {"backend": "s3", "bucket": "models", "key": "models/model.npz", "version_id": "v1",
                    "sha256": sha(content), "size_bytes": len(content), "model_digest": "d" * 64}
        campaign.s3 = Mock()
        campaign.s3.get_object.return_value = {"Body": io.BytesIO(content)}
        campaign.export_objects(artifact, campaign.output)
        path = Path(artifact["local_export"]["path"])
        self.assertEqual(len(path.name), 24)
        self.assertEqual(artifact["local_export"]["file_sha256"], sha(path.read_bytes()))
        path.write_bytes(b"modified retained export")
        campaign.s3.get_object.return_value = {"Body": io.BytesIO(content)}
        with self.assertRaisesRegex(ValueError, "collision_or_modified"):
            campaign.export_objects(artifact, campaign.output)


if __name__ == "__main__":
    unittest.main()
