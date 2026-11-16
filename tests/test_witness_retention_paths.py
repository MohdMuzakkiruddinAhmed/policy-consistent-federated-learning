"""Synthetic relative CLI paths retain ownership/traversal/link checks."""
from contextlib import chdir
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=next(path for path in Path(__file__).resolve().parents if (path/'pyproject.toml').is_file())
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests'),str(ROOT/'src')]
import witness_retention as retention
import test_witness_retention as fixtures


class WitnessRetentionPathTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.WitnessRetentionTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture
        self.relative=Path('results/aws/synthetic-campaign/inventory.json')
        self.public=Path('results/aws/synthetic-campaign/operator-witness-public.pem')

    def invoke(self,path=None,*,apply=False):
        return retention.backfill_inventory(self.relative if path is None else path,public_key_path=self.public,
            expected_public_key_sha256=self.f.pin,expected_inventory_sha256=hashlib.sha256(self.f.path.read_bytes()).hexdigest(),
            apply=apply,clients={'sts':self.f.sts,'s3':self.f.s3})

    def test_relative_inventory_preview_reads_once_without_AWS_or_mutation(self):
        before=self.f.path.read_bytes()
        with chdir(self.f.root),patch.object(retention,'ROOT',self.f.root):result=self.invoke()
        self.assertFalse(result['aws_calls']);self.assertEqual(result['recorded_witnesses_proposed'],1)
        self.assertEqual(before,self.f.path.read_bytes());self.f.sts.get_caller_identity.assert_not_called();self.f.s3.get_object.assert_not_called()

    def test_relative_apply_and_idempotent_retry_match_absolute_contract(self):
        with chdir(self.f.root),patch.object(retention,'ROOT',self.f.root):
            first=self.invoke(apply=True);before=self.f.path.read_bytes();second=self.invoke(apply=True)
        self.assertEqual(first['versions_added'],1);self.assertEqual(second['versions_added'],0)
        self.assertEqual(before,self.f.path.read_bytes());self.assertEqual(first['receipt'],second['receipt'])
        self.f.s3.put_object.assert_not_called();self.f.s3.delete_objects.assert_not_called()

    def test_relative_and_absolute_explicit_parent_traversal_reject_before_SDK(self):
        before=self.f.path.read_bytes()
        for path in (Path('results/aws/synthetic-campaign/../synthetic-campaign/inventory.json'),
                self.f.directory/'..'/'synthetic-campaign'/'inventory.json'):
            with chdir(self.f.root),patch.object(retention,'ROOT',self.f.root),self.assertRaisesRegex(ValueError,'outside'):
                self.invoke(path,apply=True)
        self.assertEqual(before,self.f.path.read_bytes());self.f.sts.get_caller_identity.assert_not_called();self.f.s3.get_object.assert_not_called()

    def test_relative_link_ancestry_is_checked_before_canonical_resolution_or_SDK(self):
        original=Path.is_symlink
        def is_link(path):
            return path==self.f.directory or original(path)
        before=self.f.path.read_bytes()
        with chdir(self.f.root),patch.object(retention,'ROOT',self.f.root),patch.object(Path,'is_symlink',is_link),self.assertRaisesRegex(ValueError,'linked'):
            self.invoke(apply=True)
        self.assertEqual(before,self.f.path.read_bytes());self.f.sts.get_caller_identity.assert_not_called();self.f.s3.get_object.assert_not_called()
