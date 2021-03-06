#!/usr/bin/env python
# coding: utf-8

import io
import os
import sys
import uuid
import json
import argparse
import unittest
import string
import random
import copy
import datetime
import tempfile
import typing
from collections import namedtuple
from unittest import mock
from boto3.s3.transfer import TransferConfig
from botocore.exceptions import ClientError

from cloud_blobstore import BlobNotFoundError

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from tests import skip_on_travis
from tests.infra import testmode
from dss.operations import DSSOperationsCommandDispatch
from dss.operations.util import map_bucket_results
from dss.operations import checkout, storage, sync, secrets, lambda_params, iam, events, flac
from dss.operations.lambda_params import get_deployed_lambdas, fix_ssm_variable_prefix
from dss.operations.iam import IAMSEPARATOR
from dss.operations.secrets import SecretsChecker
from dss.logging import configure_test_logging
from dss.config import BucketConfig, Config, Replica, override_bucket_config
from dss.storage.hcablobstore import FileMetadata, compose_blob_key
from dss.storage.identifiers import UUID_REGEX
from dss.util.version import datetime_to_version_format
from tests import CaptureStdout, SwapStdin
from tests.test_bundle import TestBundleApiMixin
from tests.infra import get_env, DSSUploadMixin, TestAuthMixin, DSSAssertMixin
from tests.infra.server import ThreadedLocalServer


def setUpModule():
    configure_test_logging()

def random_alphanumeric_string(N=10):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))


@testmode.standalone
class TestOperations(unittest.TestCase):
    def test_dispatch(self):
        with self.subTest("dispatch without mutually exclusive arguments"):
            self._test_dispatch()

        with self.subTest("dispatch with mutually exclusive arguments"):
            self._test_dispatch(mutually_exclusive=True)

        with self.subTest("dispatch with action overrides"):
            self._test_dispatch(action_overrides=True)

    def _test_dispatch(self, mutually_exclusive=None, action_overrides=False):
        dispatch = DSSOperationsCommandDispatch()
        target = dispatch.target(
            "my_target",
            arguments={
                "foo": dict(default="george", type=int),
                "--argument-a": None,
                "--argument-b": dict(default="bar"),
            },
            mutually_exclusive=(["--argument-a", "--argument-b"] if mutually_exclusive else None)
        )

        if action_overrides:
            @target.action("my_action", arguments={"foo": None, "--bar": dict(default="bars")})
            def my_action(argv, args):
                self.assertEqual(args.argument_b, "LSDKFJ")
                self.assertEqual(args.foo, "24")
                self.assertEqual(args.bar, "bars")
        else:
            @target.action("my_action")
            def my_action(argv, args):
                self.assertEqual(args.argument_b, "LSDKFJ")
                self.assertEqual(args.foo, 24)

        dispatch(["my_target", "my_action", "24", "--argument-b", "LSDKFJ"])

    def test_map_bucket(self):
        with override_bucket_config(BucketConfig.TEST_FIXTURE):
            for replica in Replica:
                with self.subTest(replica=replica):
                    handle = Config.get_blobstore_handle(replica)

                    count_list = 0
                    for key in handle.list(replica.bucket, prefix="bundles/"):
                        count_list += 1

                    def counter(keys):
                        count = 0
                        for key in keys:
                            count += 1
                        return count

                    total = 0
                    for count in map_bucket_results(counter, handle, replica.bucket, "bundles/", 2):
                        total += count

                    self.assertGreater(count_list, 0)
                    self.assertEqual(count_list, total)

    def test_repair_blob_metadata(self):
        uploader = {Replica.aws: self._put_s3_file, Replica.gcp: self._put_gs_file}
        with override_bucket_config(BucketConfig.TEST):
            for replica in Replica:
                handle = Config.get_blobstore_handle(replica)
                key = str(uuid.uuid4())
                file_metadata = {
                    FileMetadata.SHA256: "foo",
                    FileMetadata.SHA1: "foo",
                    FileMetadata.S3_ETAG: "foo",
                    FileMetadata.CRC32C: "foo",
                    FileMetadata.CONTENT_TYPE: "foo"
                }
                blob_key = compose_blob_key(file_metadata)
                uploader[replica](key, json.dumps(file_metadata).encode("utf-8"), "application/json")
                uploader[replica](blob_key, b"123", "bar")
                args = argparse.Namespace(keys=[key], entity_type="files", job_id="", replica=replica.name)

                with self.subTest("Blob content type repaired", replica=replica):
                    storage.repair_file_blob_metadata([], args).process_key(key)
                    self.assertEqual(handle.get_content_type(replica.bucket, blob_key),
                                     file_metadata[FileMetadata.CONTENT_TYPE])

                with self.subTest("Should handle arbitrary exceptions", replica=replica):
                    with mock.patch("dss.operations.storage.StorageOperationHandler.log_error") as log_error:
                        with mock.patch("dss.config.Config.get_native_handle") as thrower:
                            thrower.side_effect = Exception()
                            storage.repair_file_blob_metadata([], args).process_key(key)
                            log_error.assert_called()
                            self.assertEqual(log_error.call_args[0][0], "Exception")

                with self.subTest("Should handle missing file metadata", replica=replica):
                    with mock.patch("dss.operations.storage.StorageOperationHandler.log_warning") as log_warning:
                        storage.repair_file_blob_metadata([], args).process_key("wrong key")
                        self.assertEqual(log_warning.call_args[0][0], "BlobNotFoundError")

                with self.subTest("Should handle missing blob", replica=replica):
                    with mock.patch("dss.operations.storage.StorageOperationHandler.log_warning") as log_warning:
                        file_metadata[FileMetadata.SHA256] = "wrong"
                        uploader[replica](key, json.dumps(file_metadata).encode("utf-8"), "application/json")
                        storage.repair_file_blob_metadata([], args).process_key(key)
                        self.assertEqual(log_warning.call_args[0][0], "BlobNotFoundError")

                with self.subTest("Should handle corrupt file metadata", replica=replica):
                    with mock.patch("dss.operations.storage.StorageOperationHandler.log_warning") as log_warning:
                        uploader[replica](key, b"this is not json", "application/json")
                        storage.repair_file_blob_metadata([], args).process_key(key)
                        self.assertEqual(log_warning.call_args[0][0], "JSONDecodeError")

    def test_bundle_reference_list(self):
        class MockHandler:
            mock_file_data = {"uuid": "987",
                              "version": "987",
                              "sha256": "256k",
                              "sha1": "1thing",
                              "s3-etag": "s34me",
                              "crc32c": "wthisthis"}
            mock_bundle_metadata = {"files": [mock_file_data]}
            mock_bundle_key = 'bundles/123.456'
            handle = mock.Mock()

            def get(self, bucket, key):
                return json.dumps(self.mock_bundle_metadata)

        for replica in Replica:
            with self.subTest("Test Bundle Reference"):
                with override_bucket_config(BucketConfig.TEST):
                    with mock.patch("dss.operations.storage.Config") as mock_handle:
                        mock_handle.get_blobstore_handle = mock.MagicMock(return_value=MockHandler())
                        args = argparse.Namespace(keys=[MockHandler.mock_bundle_key],
                                                  replica=replica.name,
                                                  entity_type='bundles',
                                                  job_id="")
                        res = storage.build_reference_list([], args).process_key(MockHandler.mock_bundle_key)
                        self.assertIn(MockHandler.mock_bundle_key, res)
                        self.assertIn(f'files/{MockHandler.mock_file_data["uuid"]}.'
                                      f'{MockHandler.mock_file_data["version"]}',
                                      res)
                        self.assertIn(compose_blob_key(MockHandler.mock_file_data), res)

    def test_update_content_type(self):
        TestCase = namedtuple("TestCase", "replica upload size update initial_content_type expected_content_type")
        with override_bucket_config(BucketConfig.TEST):
            key = f"operations/{uuid.uuid4()}"
            large_size = 64 * 1024 * 1024 + 1
            tests = [
                TestCase(Replica.aws, self._put_s3_file, 1, storage.update_aws_content_type, "a", "b"),
                TestCase(Replica.aws, self._put_s3_file, large_size, storage.update_aws_content_type, "a", "b"),
                TestCase(Replica.gcp, self._put_gs_file, 1, storage.update_gcp_content_type, "a", "b"),
            ]
            for test in tests:
                data = os.urandom(test.size)
                with self.subTest(test.replica.name):
                    handle = Config.get_blobstore_handle(test.replica)
                    native_handle = Config.get_native_handle(test.replica)
                    test.upload(key, data, test.initial_content_type)
                    old_checksum = handle.get_cloud_checksum(test.replica.bucket, key)
                    test.update(native_handle, test.replica.bucket, key, test.expected_content_type)
                    self.assertEqual(test.expected_content_type, handle.get_content_type(test.replica.bucket, key))
                    self.assertEqual(handle.get(test.replica.bucket, key), data)
                    self.assertEqual(old_checksum, handle.get_cloud_checksum(test.replica.bucket, key))

    def test_verify_blob_replication(self):
        key = "blobs/alsdjflaskjdf"
        from_handle = mock.Mock()
        to_handle = mock.Mock()
        from_handle.get_size = mock.Mock(return_value=10)
        to_handle.get_size = mock.Mock(return_value=10)

        with self.subTest("no replication error"):
            res = sync.verify_blob_replication(from_handle, to_handle, "", "", key)
            self.assertEqual(res, list())

        with self.subTest("Unequal size blobs reports error"):
            to_handle.get_size = mock.Mock(return_value=11)
            res = sync.verify_blob_replication(from_handle, to_handle, "", "", key)
            self.assertEqual(res[0].key, key)
            self.assertIn("mismatch", res[0].anomaly)

        with self.subTest("Missing target blob reports error"):
            to_handle.get_size.side_effect = BlobNotFoundError
            res = sync.verify_blob_replication(from_handle, to_handle, "", "", key)
            self.assertEqual(res[0].key, key)
            self.assertIn("missing", res[0].anomaly)

    def test_verify_file_replication(self):
        key = "blobs/alsdjflaskjdf"
        from_handle = mock.Mock()
        to_handle = mock.Mock()
        file_metadata = json.dumps({'sha256': "", 'sha1': "", 's3-etag': "", 'crc32c': ""})
        from_handle.get = mock.Mock(return_value=file_metadata)
        to_handle.get = mock.Mock(return_value=file_metadata)

        with self.subTest("no replication error"):
            with mock.patch("dss.operations.sync.verify_blob_replication") as vbr:
                vbr.return_value = list()
                res = sync.verify_file_replication(from_handle, to_handle, "", "", key)
                self.assertEqual(res, list())

        with self.subTest("Unequal file metadata"):
            to_handle.get.return_value = "{}"
            res = sync.verify_file_replication(from_handle, to_handle, "", "", key)
            self.assertEqual(res[0].key, key)
            self.assertIn("mismatch", res[0].anomaly)

        with self.subTest("Missing file metadata"):
            to_handle.get.side_effect = BlobNotFoundError
            res = sync.verify_file_replication(from_handle, to_handle, "", "", key)
            self.assertEqual(res[0].key, key)
            self.assertIn("missing", res[0].anomaly)

    def test_verify_bundle_replication(self):
        key = "blobs/alsdjflaskjdf"
        from_handle = mock.Mock()
        to_handle = mock.Mock()
        bundle_metadata = json.dumps({
            "creator_uid": 8008,
            "files": [{"uuid": None, "version": None}]
        })
        from_handle.get = mock.Mock(return_value=bundle_metadata)
        to_handle.get = mock.Mock(return_value=bundle_metadata)

        with mock.patch("dss.operations.sync.verify_file_replication") as vfr:
            with self.subTest("replication ok"):
                vfr.return_value = list()
                res = sync.verify_bundle_replication(from_handle, to_handle, "", "", key)
                self.assertEqual(res, [])

            with self.subTest("replication problem"):
                vfr.return_value = [sync.ReplicationAnomaly(key="", anomaly="")]
                res = sync.verify_bundle_replication(from_handle, to_handle, "", "", key)
                self.assertEqual(res, vfr.return_value)

            with self.subTest("Unequal bundle metadata"):
                to_handle.get.return_value = "{}"
                res = sync.verify_bundle_replication(from_handle, to_handle, "", "", key)
                self.assertEqual(res[0].key, key)
                self.assertIn("mismatch", res[0].anomaly)

            with self.subTest("Missing destination bundle metadata"):
                to_handle.get.side_effect = BlobNotFoundError
                res = sync.verify_bundle_replication(from_handle, to_handle, "", "", key)
                self.assertEqual(res[0].key, key)
                self.assertIn("missing on target", res[0].anomaly)

            with self.subTest("Missing source bundle metadata"):
                from_handle.get.side_effect = BlobNotFoundError
                res = sync.verify_bundle_replication(from_handle, to_handle, "", "", key)
                self.assertEqual(res[0].key, key)
                self.assertIn("missing on source", res[0].anomaly)

    def _put_s3_file(self, key, data, content_type="blah", part_size=None):
        s3 = Config.get_native_handle(Replica.aws)
        with io.BytesIO(data) as fh:
            s3.upload_fileobj(Bucket=Replica.aws.bucket,
                              Key=key,
                              Fileobj=fh,
                              ExtraArgs=dict(ContentType=content_type),
                              Config=TransferConfig(multipart_chunksize=64 * 1024 * 1024))

    def _put_gs_file(self, key, data, content_type="blah"):
        gs = Config.get_native_handle(Replica.gcp)
        gs_bucket = gs.bucket(Replica.gcp.bucket)
        gs_blob = gs_bucket.blob(key, chunk_size=1 * 1024 * 1024)
        with io.BytesIO(data) as fh:
            gs_blob.upload_from_file(fh, content_type="application/octet-stream")

    def test_iam_aws_list_policies(self):

        def _get_aws_list_policies_kwargs(**kwargs):
            # Set default kwarg values, then set any user-specified kwargs
            custom_kwargs = dict(
                cloud_provider="aws",
                group_by=None,
                output=None,
                force=False,
                include_managed=False,
                exclude_headers=False,
                quiet=True
            )
            for kw, val in kwargs.items():
                custom_kwargs[kw] = val
            return custom_kwargs

        def _get_fake_policy_document():
            """Utility function to get a fake policy document for mocking the AWS API"""
            return {
                "Version": "2000-01-01",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["fakeservice:*"],
                        "Resource": [
                            "arn:aws:fakeservice:us-east-1:861229788715:foo:bar*",
                            "arn:aws:fakeservice:us-east-1:861229788715:foo:bar/baz*",
                        ],
                    }
                ],
            }

        with self.subTest("List AWS policies"):
            with mock.patch("dss.operations.iam.iam_client") as iam_client:
                # calling list_policies() will call list_aws_policies()
                # which will call extract_aws_policies()
                # which will call get_paginator("list_policies")
                # which will call paginate() to ask for each page,
                # and ask for ["Policies"] for the page items,
                # and ["PolicyName"] for the items
                class MockPaginator(object):
                    def paginate(self, *args, **kwargs):
                        # Return a mock page from the mock paginator
                        return [{"Policies": [{"PolicyName": "fake-policy"}]}]

                # Plain call to list_policies
                iam_client.get_paginator.return_value = MockPaginator()
                with CaptureStdout() as output:
                    kwargs = _get_aws_list_policies_kwargs()
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn("fake-policy", output)

                # Check write to output file
                temp_prefix = "dss-test-operations-iam-aws-list-temp-output"
                f, fname = tempfile.mkstemp(prefix=temp_prefix)
                iam_client.get_paginator.return_value = MockPaginator()
                kwargs = _get_aws_list_policies_kwargs(output=fname, force=True)
                iam.list_policies([], argparse.Namespace(**kwargs))
                with open(fname, "r") as f:
                    output = f.read()
                self.assertIn("fake-policy", output)

        # Define utility functions and classes to help test the --group-by flags
        def _get_detail_lists(asset_type):
            """Utility function to return a fake user detail list for mocking AWS API"""
            if asset_type not in ['users', 'groups', 'roles']:
                raise RuntimeError("Error: invalid asset type given, cannot mock AWS API")

            user_detail_list = [
                {
                    "UserName": "fake-user-1",
                    "UserId": random_alphanumeric_string(N=21).upper(),
                    "AttachedManagedPolicies": [],
                    "UserPolicyList": [
                        {
                            "PolicyName": "fake-policy-attached-to-fake-user-1",
                            "PolicyDocument": _get_fake_policy_document(),
                        }
                    ],
                }
            ]

            group_detail_list = [
                {
                    "GroupName": "fake-group-1",
                    "GroupId": random_alphanumeric_string(N=21).upper(),
                    "AttachedManagedPolicies": [],
                    "GroupPolicyList": [
                        {
                            "PolicyName": "fake-policy-attached-to-fake-group-1",
                            "PolicyDocument": _get_fake_policy_document(),
                        }
                    ],
                }
            ]

            role_detail_list = [
                {
                    "RoleName": "fake-role-1",
                    "RoleId": random_alphanumeric_string(N=21).upper(),
                    "AttachedManagedPolicies": [],
                    "RolePolicyList": [
                        {
                            "PolicyName": "fake-policy-attached-to-fake-role-1",
                            "PolicyDocument": _get_fake_policy_document(),
                        }
                    ],
                }
            ]

            return {
                "GroupDetailList": group_detail_list if asset_type == "groups" else [],
                "RoleDetailList": role_detail_list if asset_type == "roles" else [],
                "UserDetailList": user_detail_list if asset_type == "users" else [],
            }

        class MockPaginator_UserPolicies(object):
            def paginate(self, *args, **kwargs):
                yield _get_detail_lists("users")

        class MockPaginator_GroupPolicies(object):
            def paginate(self, *args, **kwargs):
                yield _get_detail_lists("groups")

        class MockPaginator_RolePolicies(object):
            def paginate(self, *args, **kwargs):
                yield _get_detail_lists("roles")

        with self.subTest("List AWS policies grouped by user"):
            with mock.patch("dss.operations.iam.iam_client") as iam_client:
                # this will call list_aws_user_policies()
                # which will call list_aws_policies_grouped()
                # which will call get_paginator("get_account_authorization_details")
                # (this is what we mock)
                # then it calls paginate() to ask for each page,
                # which we mock in the mock classes above.
                iam_client.get_paginator.return_value = MockPaginator_UserPolicies()

                # Plain call to list_policies
                with CaptureStdout() as output:
                    kwargs = _get_aws_list_policies_kwargs(group_by="users")
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn(IAMSEPARATOR.join(["fake-user-1", "fake-policy-attached-to-fake-user-1"]), output)

                # Check write to output file
                temp_prefix = "dss-test-operations-iam-aws-list-users-temp-output"
                f, fname = tempfile.mkstemp(prefix=temp_prefix)
                iam_client.get_paginator.return_value = MockPaginator_UserPolicies()
                kwargs = _get_aws_list_policies_kwargs(group_by="users", output=fname, force=True)
                iam.list_policies([], argparse.Namespace(**kwargs))
                with open(fname, "r") as f:
                    output = f.read()
                self.assertIn(
                    IAMSEPARATOR.join(["fake-user-1", "fake-policy-attached-to-fake-user-1"]), output
                )

        with self.subTest("List AWS policies grouped by user"):
            with mock.patch("dss.operations.iam.iam_client") as iam_client:
                # calls list_aws_group_policies
                # then list_aws_policies_grouped
                # then get_paginator("get_account_authorization_details")
                # (this is what we mock)
                iam_client.get_paginator.return_value = MockPaginator_GroupPolicies()

                # Plain call to list_policies
                with CaptureStdout() as output:
                    kwargs = _get_aws_list_policies_kwargs(group_by="groups")
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn(
                    IAMSEPARATOR.join(["fake-group-1", "fake-policy-attached-to-fake-group-1"]), output
                )

                # Check write to output file
                temp_prefix = "dss-test-operations-iam-aws-list-groups-temp-output"
                f, fname = tempfile.mkstemp(prefix=temp_prefix)
                iam_client.get_paginator.return_value = MockPaginator_GroupPolicies()
                kwargs = _get_aws_list_policies_kwargs(group_by="groups", output=fname, force=True)
                iam.list_policies([], argparse.Namespace(**kwargs))
                with open(fname, "r") as f:
                    output = f.read()
                self.assertIn(
                    IAMSEPARATOR.join(["fake-group-1", "fake-policy-attached-to-fake-group-1"]), output
                )

        with self.subTest("List AWS policies grouped by role"):
            with mock.patch("dss.operations.iam.iam_client") as iam_client:
                # calls list_aws_group_policies
                # then list_aws_policies_grouped
                # then get_paginator("get_account_authorization_details")
                # (this is what we mock)
                iam_client.get_paginator.return_value = MockPaginator_RolePolicies()

                # Plain call to list_policies
                with CaptureStdout() as output:
                    kwargs = _get_aws_list_policies_kwargs(group_by="roles")
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn(
                    IAMSEPARATOR.join(["fake-role-1", "fake-policy-attached-to-fake-role-1"]), output
                )

                # Check write to output file
                temp_prefix = "dss-test-operations-iam-aws-list-roles-temp-output"
                f, fname = tempfile.mkstemp(prefix=temp_prefix)
                iam_client.get_paginator.return_value = MockPaginator_RolePolicies()
                kwargs = _get_aws_list_policies_kwargs(group_by="roles", output=fname, force=True)
                iam.list_policies([], argparse.Namespace(**kwargs))
                with open(fname, "r") as f:
                    output = f.read()
                self.assertIn(
                    IAMSEPARATOR.join(["fake-role-1", "fake-policy-attached-to-fake-role-1"]), output
                )

                # Make sure we can't overwrite without --force
                with self.assertRaises(RuntimeError):
                    kwargs = _get_aws_list_policies_kwargs(group_by="roles", output=fname, force=False)
                    iam.list_policies([], argparse.Namespace(**kwargs))

        # Test error-handling and exceptions last
        with self.subTest("Test exceptions and error-handling for AWS IAM functions in dss-ops"):

            with self.assertRaises(RuntimeError):
                kwargs = _get_aws_list_policies_kwargs(cloud_provider="invalid-cloud-provider")
                iam.list_policies([], argparse.Namespace(**kwargs))

            with self.assertRaises(RuntimeError):
                kwargs = _get_aws_list_policies_kwargs(group_by="another-invalid-choice")
                iam.list_policies([], argparse.Namespace(**kwargs))

    def test_iam_fus_list_policies(self):

        def _get_fus_list_policies_kwargs(**kwargs):
            # Set default kwargs values, then set user-specified kwargs
            custom_kwargs = dict(
                cloud_provider="fusillade",
                group_by=None,
                output=None,
                force=False,
                exclude_headers=False,
                include_managed=False,
                quiet=True
            )
            for kw, val in kwargs.items():
                custom_kwargs[kw] = val
            return custom_kwargs

        with self.subTest("Fusillade client"):
            with mock.patch("dss.operations.iam.DCPServiceAccountManager") as SAM, \
                    mock.patch("dss.operations.iam.requests") as req:

                # Mock the service account manager so it won't hit the fusillade server
                class FakeServiceAcctMgr(object):

                    def get_authorization_header(self, *args, **kwargs):
                        return {}

                SAM.from_secrets_manager = mock.MagicMock(return_value=FakeServiceAcctMgr())

                # Create fake API response (one page)
                class FakeResponse(object):

                    def __init__(self):
                        self.headers = {}

                    def raise_for_status(self, *args, **kwargs):
                        pass

                    def json(self, *args, **kwargs):
                        return {"key": "value"}

                # Test call_api()
                req.get = mock.MagicMock(return_value=FakeResponse())
                client = iam.FusilladeClient("testing")
                result = client.call_api("/foobar", "key")
                self.assertEqual(result, "value")

                # Mock paginated responses with and without Link header
                class FakePaginatedResponse(object):

                    def __init__(self):
                        self.headers = {}

                    def raise_for_status(self, *args, **kwargs):
                        pass

                    def json(self, *args, **kwargs):
                        return {"key": ["values", "values"]}

                class FakePaginatedResponseWithLink(FakePaginatedResponse):

                    def __init__(self):
                        self.headers = {"Link": "<https://api.github.com/user/repos?page=3&per_page=100>;"}

                # Test paginate()
                req.get = mock.MagicMock(side_effect=[FakePaginatedResponseWithLink(), FakePaginatedResponse()])
                result = client.paginate("/foobar", "key")
                self.assertEqual(result, ["values"] * 4)

        def _wrap_policy(policy_doc):
            """Wrap a policy doc the way Fusillade stores/returns them"""
            return {"IAMPolicy": policy_doc}

        def _repatch_fus_client(fus_client):
            """
            Re-patch a mock Fusillade client with the proper responses for no --group-by flag
            or for the --group-by users flag.
            """
            # When we call list_policies(), which calls list_fus_user_policies(),
            # it calls the paginate() method to get a list of all users,
            # then the paginate() method twice for each user (once for groups, once for roles),
            side_effects = [
                [
                    "fake-user@test-operations.data.humancellatlas.org",
                    "another-fake-user@test-operations.data.humancellatlas.org"
                ],
                ["fake-group"], ["fake-role"],
                ["fake-group-2"], ["fake-role-2"]
            ]
            fus_client().paginate = mock.MagicMock(side_effect=side_effects)

            # Once we have called the paginate() methods,
            # we call the call_api() method to get IAM policies attached to roles and groups
            policy_docs = [
                '{"Id": "fake-group-policy"}',
                '{"Id": "fake-role-policy"}',
                '{"Id": "fake-group-2-policy"}',
                '{"Id": "fake-role-2-policy"}',
            ]
            fus_client().call_api = mock.MagicMock(side_effect=[_wrap_policy(doc) for doc in policy_docs])

        with self.subTest("List Fusillade policies"):

            with mock.patch("dss.operations.iam.FusilladeClient") as fus_client:
                # Note: Need to call _repatch_fus_client() before each test

                # Plain call to list_fus_policies
                with CaptureStdout() as output:
                    _repatch_fus_client(fus_client)
                    kwargs = _get_fus_list_policies_kwargs()
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn("fake-group-policy", output)
                self.assertIn("fake-role-policy", output)
                self.assertIn("fake-group-2-policy", output)
                self.assertIn("fake-role-2-policy", output)

                # Check exclude headers
                with CaptureStdout() as output:
                    _repatch_fus_client(fus_client)
                    kwargs = _get_fus_list_policies_kwargs(exclude_headers=True)
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn("fake-group-policy", output)
                self.assertIn("fake-role-policy", output)
                self.assertIn("fake-group-2-policy", output)
                self.assertIn("fake-role-2-policy", output)

                # Check write to output file
                temp_prefix = "dss-test-operations-iam-fus-list-temp-output"
                f, fname = tempfile.mkstemp(prefix=temp_prefix)
                _repatch_fus_client(fus_client)
                kwargs = _get_fus_list_policies_kwargs(output=fname, force=True)
                iam.list_policies([], argparse.Namespace(**kwargs))
                with open(fname, "r") as f:
                    output = f.read()
                self.assertIn("fake-group-policy", output)
                self.assertIn("fake-role-policy", output)
                self.assertIn("fake-group-2-policy", output)
                self.assertIn("fake-role-2-policy", output)

        with self.subTest("List Fusillade policies grouped by users"):

            with mock.patch("dss.operations.iam.FusilladeClient") as fus_client:

                # List fusillade policies grouped by user
                with CaptureStdout() as output:
                    _repatch_fus_client(fus_client)
                    kwargs = _get_fus_list_policies_kwargs(group_by="users")
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn(IAMSEPARATOR.join([
                    "fake-user@test-operations.data.humancellatlas.org", "fake-group-policy"
                ]), output)
                self.assertIn(IAMSEPARATOR.join([
                    "fake-user@test-operations.data.humancellatlas.org", "fake-role-policy"
                ]), output)
                self.assertIn(IAMSEPARATOR.join([
                    "another-fake-user@test-operations.data.humancellatlas.org", "fake-group-2-policy"
                ]), output)
                self.assertIn(IAMSEPARATOR.join([
                    "another-fake-user@test-operations.data.humancellatlas.org", "fake-role-2-policy"
                ]), output)

                # Check exclude headers
                with CaptureStdout() as output:
                    _repatch_fus_client(fus_client)
                    kwargs = _get_fus_list_policies_kwargs(group_by="users", exclude_headers=True)
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn(IAMSEPARATOR.join([
                    "fake-user@test-operations.data.humancellatlas.org", "fake-group-policy"
                ]), output)
                self.assertIn(IAMSEPARATOR.join([
                    "fake-user@test-operations.data.humancellatlas.org", "fake-role-policy"
                ]), output)
                self.assertIn(IAMSEPARATOR.join([
                    "another-fake-user@test-operations.data.humancellatlas.org", "fake-group-2-policy"
                ]), output)
                self.assertIn(IAMSEPARATOR.join([
                    "another-fake-user@test-operations.data.humancellatlas.org", "fake-role-2-policy"
                ]), output)

                # Check write to output file
                temp_prefix = "dss-test-operations-iam-fus-list-users-temp-output"
                f, fname = tempfile.mkstemp(prefix=temp_prefix)
                _repatch_fus_client(fus_client)
                kwargs = _get_fus_list_policies_kwargs(group_by="users", output=fname, force=True)
                iam.list_policies([], argparse.Namespace(**kwargs))
                with open(fname, "r") as f:
                    output = f.read()
                self.assertIn(IAMSEPARATOR.join([
                    "fake-user@test-operations.data.humancellatlas.org", "fake-group-policy"
                ]), output)
                self.assertIn(IAMSEPARATOR.join([
                    "fake-user@test-operations.data.humancellatlas.org", "fake-role-policy"
                ]), output)
                self.assertIn(IAMSEPARATOR.join([
                    "another-fake-user@test-operations.data.humancellatlas.org", "fake-group-2-policy"
                ]), output)
                self.assertIn(IAMSEPARATOR.join([
                    "another-fake-user@test-operations.data.humancellatlas.org", "fake-role-2-policy"
                ]), output)

        with self.subTest("List Fusillade policies grouped by groups"):

            # We can't use _repatch_fus_client() to repatch,
            # since grouping by groups makes different function calls
            def _repatch_fus_client_groups(fus_client):
                """Re-patch a mock Fusillade client with the proper responses for using the --group-by groups flag"""
                # When we call list_policies(), which calls list_fus_group_policies(),
                # it calls paginate() to get all groups,
                # then calls paginate() to get roles for each group
                responses = [["fake-group", "fake-group-2"], ["fake-role"], ["fake-role-2"]]
                fus_client().paginate = mock.MagicMock(side_effect=responses)

                # For each role, list_fus_group_policies() calls get_fus_role_attached_policies(),
                # which calls call_api() on each role and returns a corresponding policy document
                # @chmreid TODO: should this be calling get policy on each group, too? (inline policies)
                policy_docs = ['{"Id": "fake-role-policy"}', '{"Id": "fake-role-2-policy"}']
                fus_client().call_api = mock.MagicMock(side_effect=[_wrap_policy(doc) for doc in policy_docs])

            with mock.patch("dss.operations.iam.FusilladeClient") as fus_client:

                # List fusillade policies grouped by groups
                with CaptureStdout() as output:
                    _repatch_fus_client_groups(fus_client)
                    kwargs = _get_fus_list_policies_kwargs(group_by="groups")
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn(IAMSEPARATOR.join(["fake-group", "fake-role-policy"]), output)
                self.assertIn(IAMSEPARATOR.join(["fake-group-2", "fake-role-2-policy"]), output)

                # Check exclude headers
                with CaptureStdout() as output:
                    _repatch_fus_client_groups(fus_client)
                    kwargs = _get_fus_list_policies_kwargs(group_by="groups", exclude_headers=True)
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn(IAMSEPARATOR.join(["fake-group", "fake-role-policy"]), output)
                self.assertIn(IAMSEPARATOR.join(["fake-group-2", "fake-role-2-policy"]), output)

                # Check write to output file
                temp_prefix = "dss-test-operations-iam-fus-list-groups-temp-output"
                f, fname = tempfile.mkstemp(prefix=temp_prefix)
                _repatch_fus_client_groups(fus_client)
                kwargs = _get_fus_list_policies_kwargs(group_by="groups", output=fname, force=True)
                iam.list_policies([], argparse.Namespace(**kwargs))
                with open(fname, "r") as f:
                    output = f.read()
                self.assertIn(IAMSEPARATOR.join(["fake-group", "fake-role-policy"]), output)
                self.assertIn(IAMSEPARATOR.join(["fake-group-2", "fake-role-2-policy"]), output)

        with self.subTest("List Fusillade policies grouped by roles"):

            # repatch the fusillade client for calling a list of policies grouped by roles
            def _repatch_fus_client_roles(fus_client):
                """Re-patch a mock Fusillade client with the proper responses for using the --group-by roles flag"""
                # When we call list_policies, which calls list_fus_role_policies(),
                # it calls paginate() to get the list of all roles,
                side_effects = [["fake-role", "fake-role-2"]]
                fus_client().paginate = mock.MagicMock(side_effect=side_effects)

                # list_fus_role_policies then calls get_fus_role_attached_policies()
                # to get a list of policies attached to the role,
                # which calls call_api() for each role returned by the paginate command
                policy_docs = ['{"Id": "fake-role-policy"}', '{"Id": "fake-role-2-policy"}']
                fus_client().call_api = mock.MagicMock(side_effect=[_wrap_policy(doc) for doc in policy_docs])

            with mock.patch("dss.operations.iam.FusilladeClient") as fus_client:

                # List fusillade policies grouped by roles
                with CaptureStdout() as output:
                    _repatch_fus_client_roles(fus_client)
                    kwargs = _get_fus_list_policies_kwargs(group_by="roles")
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn(IAMSEPARATOR.join(["fake-role", "fake-role-policy"]), output)
                self.assertIn(IAMSEPARATOR.join(["fake-role-2", "fake-role-2-policy"]), output)

                # Check exclude headers
                with CaptureStdout() as output:
                    _repatch_fus_client_roles(fus_client)
                    kwargs = _get_fus_list_policies_kwargs(group_by="roles", exclude_headers=True)
                    iam.list_policies([], argparse.Namespace(**kwargs))
                self.assertIn(IAMSEPARATOR.join(["fake-role", "fake-role-policy"]), output)
                self.assertIn(IAMSEPARATOR.join(["fake-role-2", "fake-role-2-policy"]), output)

                # Check write to output file
                temp_prefix = "dss-test-operations-iam-list-roles-temp-output"
                f, fname = tempfile.mkstemp(prefix=temp_prefix)
                _repatch_fus_client_roles(fus_client)
                kwargs = _get_fus_list_policies_kwargs(group_by="roles", output=fname, force=True)
                iam.list_policies([], argparse.Namespace(**kwargs))
                with open(fname, "r") as f:
                    output = f.read()
                self.assertIn(IAMSEPARATOR.join(["fake-role", "fake-role-policy"]), output)
                self.assertIn(IAMSEPARATOR.join(["fake-role-2", "fake-role-2-policy"]), output)

    def test_iam_aws_list_assets(self):

        def _get_aws_list_assets_kwargs(**kwargs):
            # Set default kwargs values, then set user-specified kwargs
            custom_kwargs = dict(
                cloud_provider="aws",
                output=None,
                force=False,
                exclude_headers=False,
            )
            for kw, val in kwargs.items():
                custom_kwargs[kw] = val
            return custom_kwargs

        with self.subTest("AWS list users"):
            with mock.patch("dss.operations.iam.iam_client") as iam_client:
                class MockPaginator_Users(object):
                    def paginate(self, *args, **kwargs):
                        return [{"Users": [
                            {"UserName": "fake-user-1@test-operations.data.humancellatlas.org"},
                            {"UserName": "fake-user-2@test-operations.data.humancellatlas.org"}
                        ]}]
                iam_client.get_paginator.return_value = MockPaginator_Users()
                with CaptureStdout() as output:
                    kwargs = _get_aws_list_assets_kwargs()
                    iam.list_users([], argparse.Namespace(**kwargs))
                self.assertIn("fake-user-1@test-operations.data.humancellatlas.org", output)
                self.assertIn("fake-user-2@test-operations.data.humancellatlas.org", output)

        with self.subTest("AWS list groups"):
            with mock.patch("dss.operations.iam.iam_client") as iam_client:
                class MockPaginator_Groups(object):
                    def paginate(self, *args, **kwargs):
                        return [{"Groups": [{"GroupName": "fake-group-1"}, {"GroupName": "fake-group-2"}]}]
                iam_client.get_paginator.return_value = MockPaginator_Groups()
                with CaptureStdout() as output:
                    kwargs = _get_aws_list_assets_kwargs()
                    iam.list_groups([], argparse.Namespace(**kwargs))
                self.assertIn("fake-group-1", output)
                self.assertIn("fake-group-2", output)

        with self.subTest("AWS list roles"):
            with mock.patch("dss.operations.iam.iam_client") as iam_client:
                class MockPaginator_Roles(object):
                    def paginate(self, *args, **kwargs):
                        return [{"Roles": [{"RoleName": "fake-role-1"}, {"RoleName": "fake-role-2"}]}]
                iam_client.get_paginator.return_value = MockPaginator_Roles()
                with CaptureStdout() as output:
                    kwargs = _get_aws_list_assets_kwargs()
                    iam.list_roles([], argparse.Namespace(**kwargs))
                self.assertIn("fake-role-1", output)
                self.assertIn("fake-role-2", output)

    def test_iam_fus_list_assets(self):

        def _get_fus_list_assets_kwargs(**kwargs):
            # Set default kwargs values, then set user-specified kwargs
            custom_kwargs = dict(
                cloud_provider="fusillade",
                output=None,
                force=False,
                exclude_headers=False,
            )
            for kw, val in kwargs.items():
                custom_kwargs[kw] = val
            return custom_kwargs

        with self.subTest("Fusillade list users"):
            with mock.patch("dss.operations.iam.FusilladeClient") as fus_client:
                side_effects = [[
                    "fake-user-1@test-operations.data.humancellatlas.org",
                    "fake-user-2@test-operations.data.humancellatlas.org"
                ]]
                fus_client().paginate = mock.MagicMock(side_effect=side_effects)
                kwargs = _get_fus_list_assets_kwargs()
                with CaptureStdout() as output:
                    iam.list_users([], argparse.Namespace(**kwargs))
                self.assertIn("fake-user-1@test-operations.data.humancellatlas.org", output)
                self.assertIn("fake-user-2@test-operations.data.humancellatlas.org", output)

        with self.subTest("Fusillade list groups"):
            with mock.patch("dss.operations.iam.FusilladeClient") as fus_client:
                side_effects = [["fake-group-1", "fake-group-2"]]
                fus_client().paginate = mock.MagicMock(side_effect=side_effects)
                kwargs = _get_fus_list_assets_kwargs()
                with CaptureStdout() as output:
                    iam.list_groups([], argparse.Namespace(**kwargs))
                self.assertIn("fake-group-1", output)
                self.assertIn("fake-group-2", output)

        with self.subTest("Fusillade list roles"):
            with mock.patch("dss.operations.iam.FusilladeClient") as fus_client:
                side_effects = [["fake-role-1", "fake-role-2"]]
                fus_client().paginate = mock.MagicMock(side_effect=side_effects)
                kwargs = _get_fus_list_assets_kwargs()
                with CaptureStdout() as output:
                    iam.list_roles([], argparse.Namespace(**kwargs))
                self.assertIn("fake-role-1", output)
                self.assertIn("fake-role-2", output)

    def test_secrets_crud(self):
        # CRUD (create read update delete) test procedure:
        # - create new secret
        # - list secrets and verify new secret shows up
        # - get secret value and verify it is correct
        # - update secret value
        # - get secret value and verify it is correct
        # - delete secret
        which_stage = os.environ["DSS_DEPLOYMENT_STAGE"]
        which_store = os.environ["DSS_SECRETS_STORE"]

        secret_name = random_alphanumeric_string()
        testvar_name = f"{which_store}/{which_stage}/{secret_name}"
        testvar_value = "Hello world!"
        testvar_value2 = "Goodbye world!"

        unusedvar_name = f"{which_store}/{which_stage}/admin_user_emails"

        with self.subTest("Create a new secret"):
            # Monkeypatch the secrets manager
            with mock.patch("dss.operations.secrets.sm_client") as sm:
                # Creating a new variable will first call get, which will not find it
                sm.get_secret_value = mock.MagicMock(return_value=None, side_effect=ClientError({}, None))
                # Next we will use the create secret command
                sm.create_secret = mock.MagicMock(return_value=None)

                # Create initial secret value:
                # Dry run first
                with SwapStdin(testvar_value):
                    secrets.set_secret(
                        [],
                        argparse.Namespace(
                            secret_name=testvar_name, dry_run=True, infile=None, quiet=True, force=True
                        ),
                    )

                # Provide secret via stdin
                with SwapStdin(testvar_value):
                    secrets.set_secret(
                        [],
                        argparse.Namespace(
                            secret_name=testvar_name, dry_run=False, infile=None, quiet=True, force=True
                        ),
                    )

                # Provide secret via infile
                with tempfile.NamedTemporaryFile(prefix='dss-test-operations-new-secret-temp-input', mode='w') as f:
                    f.write(testvar_value)
                    secrets.set_secret(
                        [],
                        argparse.Namespace(
                            secret_name=testvar_name, dry_run=False, infile=f.name, force=True, quiet=True
                        ),
                    )

                # Check error-catching with non-existent infile
                mf = 'this-file-is-not-here'
                with self.assertRaises(RuntimeError):
                    secrets.set_secret(
                        [],
                        argparse.Namespace(
                            secret_name=testvar_name, dry_run=False, infile=mf, force=True, quiet=True
                        ),
                    )

        with self.subTest("List secrets"):
            with mock.patch("dss.operations.secrets.sm_client") as sm:
                # Listing secrets requires creating a paginator first,
                # so mock what the paginator returns
                class MockPaginator(object):
                    def paginate(self):
                        # Return a mock page from the mock paginator
                        return [{"SecretList": [{"Name": testvar_name}, {"Name": unusedvar_name}]}]
                sm.get_paginator.return_value = MockPaginator()

                # Non-JSON output first
                with CaptureStdout() as output:
                    secrets.list_secrets([], argparse.Namespace(json=False))
                self.assertIn(testvar_name, output)

                # JSON output
                with CaptureStdout() as output:
                    secrets.list_secrets([], argparse.Namespace(json=True))
                all_secrets_output = json.loads("\n".join(output))
                self.assertIn(testvar_name, all_secrets_output)

        with self.subTest("Get secret value"):
            with mock.patch("dss.operations.secrets.sm_client") as sm:
                # Requesting the variable will try to get secret value and succeed
                sm.get_secret_value.return_value = {"SecretString": testvar_value}
                # Now run get secret value in JSON mode and non-JSON mode
                # and verify variable name/value is in both.

                # New output file
                with tempfile.NamedTemporaryFile(prefix='dss-test-operations-get-secret-temp-output', mode='w') as f:
                    # Try to overwrite outfile without --force
                    with self.assertRaises(RuntimeError):
                        secrets.get_secret(
                            [], argparse.Namespace(secret_name=testvar_name, outfile=f.name, force=False)
                        )

                    # Overwrite outfile with --force
                    secrets.get_secret(
                        [], argparse.Namespace(secret_name=testvar_name, outfile=f.name, force=True)
                    )
                    with open(f.name, 'r') as fr:
                        file_contents = fr.read()
                    self.assertIn(testvar_value, file_contents)

                # Output secret to stdout
                with CaptureStdout() as output:
                    secrets.get_secret(
                        [], argparse.Namespace(secret_name=testvar_name, outfile=None, force=False)
                    )
                self.assertIn(testvar_value, "\n".join(output))

        with self.subTest("Update existing secret"):
            with mock.patch("dss.operations.secrets.sm_client") as sm:
                # Updating the variable will try to get secret value and succeed
                sm.get_secret_value = mock.MagicMock(return_value={"SecretString": testvar_value})
                # Next we will call the update secret command
                sm.update_secret = mock.MagicMock(return_value=None)

                # Update secret:
                # Dry run first
                with SwapStdin(testvar_value2):
                    secrets.set_secret(
                        [],
                        argparse.Namespace(
                            secret_name=testvar_name, dry_run=True, infile=None, force=True, quiet=True
                        ),
                    )

                # Use stdin
                with SwapStdin(testvar_value2):
                    secrets.set_secret(
                        [],
                        argparse.Namespace(
                            secret_name=testvar_name, dry_run=False, infile=None, force=True, quiet=True
                        ),
                    )

                # Use input file
                with tempfile.NamedTemporaryFile(prefix='dss-test-operations-update-secret-temp-input', mode='w') as f:
                    f.write(testvar_value2)
                    secrets.set_secret(
                        [],
                        argparse.Namespace(
                            secret_name=testvar_name, dry_run=False, infile=f.name, force=True, quiet=True
                        ),
                    )

        with self.subTest("Delete secret"):
            with mock.patch("dss.operations.secrets.sm_client") as sm:
                # Deleting the variable will try to get secret value and succeed
                sm.get_secret_value = mock.MagicMock(return_value={"SecretString": testvar_value})
                sm.delete_secret = mock.MagicMock(return_value=None)

                # Delete secret
                # Dry run first
                secrets.del_secret(
                    [], argparse.Namespace(secret_name=testvar_name, force=True, dry_run=True, quiet=True)
                )

                # Real thing
                secrets.del_secret(
                    [], argparse.Namespace(secret_name=testvar_name, force=True, dry_run=False, quiet=True)
                )

    def test_ssmparams_utilities(self):
        prefix = f"/{os.environ['DSS_PARAMETER_STORE']}/{os.environ['DSS_DEPLOYMENT_STAGE']}"
        gold_var = f"{prefix}/dummy_variable"

        var = "dummy_variable"
        new_var = fix_ssm_variable_prefix(var)
        self.assertEqual(new_var, gold_var)

        var = "/dummy_variable"
        new_var = fix_ssm_variable_prefix(var)
        self.assertEqual(new_var, gold_var)

        var = f"{prefix}/dummy_variable"
        new_var = fix_ssm_variable_prefix(var)
        self.assertEqual(new_var, gold_var)

        var = f"{prefix}/dummy_variable/"
        new_var = fix_ssm_variable_prefix(var)
        self.assertEqual(new_var, gold_var)

    def test_ssmparams_crud(self):
        # CRUD (create read update delete) test for setting environment variables in SSM param store
        testvar_name = random_alphanumeric_string()
        testvar_value = "Hello world!"

        # Assemble environment to return
        old_env = {"DUMMY_VARIABLE": "dummy_value"}
        new_env = dict(**old_env)
        new_env[testvar_name] = testvar_value
        ssm_new_env = self._wrap_ssm_env(new_env)

        with self.subTest("Print the SSM environment"):
            with mock.patch("dss.operations.lambda_params.ssm_client") as ssm:
                # listing params will call ssm.get_parameter to get the entire environment
                ssm.get_parameter = mock.MagicMock(return_value=ssm_new_env)

                # Now call our params.py module. Output var=value on each line.
                with CaptureStdout() as output:
                    lambda_params.ssm_environment([], argparse.Namespace(json=False))
                self.assertIn(f"{testvar_name}={testvar_value}", output)

    def test_lambdaparams_crud(self):
        # CRUD (create read update delete) test for setting lambda function environment variables
        testvar_name = random_alphanumeric_string()
        testvar_value = "Hello world!"
        testvar_value2 = "Goodbye world!"

        # Assemble an old and new environment to return
        old_env = {"DUMMY_VARIABLE": "dummy_value"}
        new_env = dict(**old_env)
        new_env[testvar_name] = testvar_value

        ssm_old_env = self._wrap_ssm_env(old_env)
        ssm_new_env = self._wrap_ssm_env(new_env)

        lam_old_env = self._wrap_lambda_env(old_env)
        lam_new_env = self._wrap_lambda_env(new_env)

        with self.subTest("Create a new lambda parameter"):
            with mock.patch("dss.operations.lambda_params.ssm_client") as ssm, \
                    mock.patch("dss.operations.lambda_params.lambda_client") as lam:

                # If this is not a dry run, lambda_set in params.py
                # will update the SSM first, so we mock those first.
                # Before we have set the new test variable for the
                # first time, we will see the old environment.
                ssm.put_parameter = mock.MagicMock(return_value=None)
                ssm.get_parameter = mock.MagicMock(return_value=ssm_old_env)

                # The lambda_set func in params.py will update lambdas,
                # so we mock the calls that those will make too.
                lam.get_function = mock.MagicMock(return_value=None)
                lam.get_function_configuration = mock.MagicMock(return_value=lam_old_env)
                lam.update_function_configuration = mock.MagicMock(return_value=None)

                with SwapStdin(testvar_value):
                    lambda_params.lambda_set(
                        [], argparse.Namespace(name=testvar_name, dry_run=True, quiet=True)
                    )

                with SwapStdin(testvar_value):
                    lambda_params.lambda_set(
                        [], argparse.Namespace(name=testvar_name, dry_run=False, quiet=True)
                    )
        with self.subTest("List lambda parameters"):
            with mock.patch("dss.operations.lambda_params.lambda_client") as lam:
                # The lambda_list func in params.py calls get_deployed_lambas, which calls lam.get_function()
                # using daemon folder names (this function is called only to ensure no exception is thrown)
                lam.get_function = mock.MagicMock(return_value=None)
                # Next we call get_deployed_lambda_environment(), which calls lam.get_function_configuration
                # (this returns the mocked new env vars json)
                lam.get_function_configuration = mock.MagicMock(return_value=lam_new_env)
                # Used to specify a lambda by name
                stage = os.environ["DSS_DEPLOYMENT_STAGE"]

                # Non-JSON fmt
                with CaptureStdout() as output:
                    lambda_params.lambda_list([], argparse.Namespace(json=False))
                # Check that all deployed lambdas are present
                for lambda_name in lambda_params.get_deployed_lambdas(quiet=True):
                    self.assertIn(f"{lambda_name}", output)

                # JSON fmt
                with CaptureStdout() as output:
                    lambda_params.lambda_list([], argparse.Namespace(json=True))
                # Check that all deployed lambdas are present
                all_lams_output = json.loads("\n".join(output))
                for lambda_name in lambda_params.get_deployed_lambdas(quiet=True):
                    self.assertIn(lambda_name, all_lams_output)

        with self.subTest("Get environments of each lambda function"):
            with mock.patch("dss.operations.lambda_params.ssm_client") as ssm, \
                    mock.patch("dss.operations.lambda_params.lambda_client") as lam:

                # lambda_environment() function in dss/operations/lambda_params.py calls get_deployed_lambdas()
                #   (which only does local operations)
                # then it calls get_deployed_lambda_environment() on every lambda,
                #   which calls lambda_client.get_function() (only called to ensure no exception is thrown)
                lam.get_function = mock.MagicMock(return_value=None)
                #   then calls lambda_client.get_function_configuration()
                lam.get_function_configuration = mock.MagicMock(return_value=lam_new_env)

                # TODO: reduce copypasta

                # Non-JSON, no lambda name specified
                with CaptureStdout() as output:
                    lambda_params.lambda_environment([], argparse.Namespace(lambda_name=None, json=False))
                # Check that all deployed lambdas are present
                output = "\n".join(output)
                for lambda_name in lambda_params.get_deployed_lambdas(quiet=True):
                    self.assertIn(lambda_name, output)

                # Non-JSON, lambda name specified
                with CaptureStdout() as output:
                    lambda_params.lambda_environment([], argparse.Namespace(lambda_name=f"dss-{stage}", json=False))
                output = "\n".join(output)
                self.assertIn(f"dss-{stage}", output)

                # JSON, no lambda name specified
                with CaptureStdout() as output:
                    lambda_params.lambda_environment([], argparse.Namespace(lambda_name=None, json=True))
                # Check that all deployed lambdas are present
                all_lams_output = json.loads("\n".join(output))
                for lambda_name in lambda_params.get_deployed_lambdas(quiet=True):
                    self.assertIn(lambda_name, all_lams_output)

                # JSON, lambda name specified
                with CaptureStdout() as output:
                    lambda_params.lambda_environment([], argparse.Namespace(lambda_name=f"dss-{stage}", json=True))
                all_lams_output = json.loads("\n".join(output))
                self.assertIn(f"dss-{stage}", all_lams_output)

        with self.subTest("Update (set) existing lambda parameters"):
            with mock.patch("dss.operations.lambda_params.ssm_client") as ssm, \
                    mock.patch("dss.operations.lambda_params.lambda_client") as lam:
                # Mock the same way we did for create new param above.
                # First we mock the SSM param store
                ssm.get_parameter = mock.MagicMock(return_value=ssm_new_env)
                ssm.put_parameter = mock.MagicMock(return_value=None)
                # Next we mock the lambda client
                lam.get_function = mock.MagicMock(return_value=None)
                lam.get_function_configuration = mock.MagicMock(return_value=lam_new_env)
                lam.update_function_configuration = mock.MagicMock(return_value=None)

                # Dry run then real (mocked) thing
                with SwapStdin(testvar_value2):
                    lambda_params.lambda_set(
                        [], argparse.Namespace(name=testvar_name, dry_run=True, quiet=True)
                    )
                with SwapStdin(testvar_value2):
                    lambda_params.lambda_set(
                        [], argparse.Namespace(name=testvar_name, dry_run=False, quiet=True)
                    )

        with self.subTest("Update lambda environment stored in SSM store under $DSS_DEPLOYMENT_STAGE/environment"):
            with mock.patch("dss.operations.lambda_params.ssm_client") as ssm, \
                    mock.patch("dss.operations.lambda_params.lambda_client") as lam, \
                    mock.patch("dss.operations.lambda_params.es_client") as es, \
                    mock.patch("dss.operations.lambda_params.sm_client") as sm, \
                    mock.patch("dss.operations.lambda_params.set_ssm_environment") as set_ssm:
                # If we call lambda_update in dss/operations/lambda_params.py,
                #   it calls get_local_lambda_environment()
                #   (local operations only)
                # lambda_update() then calls set_ssm_environment(),
                #   which we mocked above into set_ssm
                set_ssm = mock.MagicMock(return_value=None) # noqa

                ssm.put_parameter = mock.MagicMock(return_value=None)

                # get_elasticsearch_endpoint() calls es.describe_elasticsearch_domain()
                es_endpoint_secret = {
                    "DomainStatus": {
                        "Endpoint": "this-invalid-es-endpoint-value-comes-from-dss-test-operations"
                    }
                }
                es.describe_elasticsearch_domain = mock.MagicMock(
                    return_value=es_endpoint_secret
                )

                # get_admin_emails() calls sm.get_secret_value() several times:
                # - google service acct secret (json string)
                # - admin email secret
                # use side_effect when returning multiple values
                google_service_acct_secret = json.dumps(
                    {"client_email": "this-invalid-email-comes-from-dss-test-operations"}
                )
                admin_email_secret = "this-invalid-email-list-comes-from-dss-test-operations"

                # Finally, we call set_ssm_environment
                # which calls ssm.put_parameter()
                # (mocked above).

                # If we also update deployed lambdas:
                # get_deployed_lambdas() -> lam_client.get_function()
                # get_deployed_lambda_environment() -> lam_client.get_function_configuration()
                # set_deployed_lambda_environment() -> lam_client.update_function_configuration()
                lam.get_function = mock.MagicMock(return_value=None)
                lam.get_function_configuration = mock.MagicMock(return_value=lam_new_env)
                lam.update_function_configuration = mock.MagicMock(return_value=None)

                # The function sm.get_secret_value() must return things in the right order
                # Re-mock it before each call
                email_side_effect = [
                    self._wrap_secret(google_service_acct_secret),
                    self._wrap_secret(admin_email_secret),
                ]

                # Dry run, then real (mocked) thing
                sm.get_secret_value = mock.MagicMock(side_effect=email_side_effect)
                lambda_params.lambda_update(
                    [], argparse.Namespace(update_deployed=False, dry_run=True, force=True, quiet=True)
                )
                sm.get_secret_value = mock.MagicMock(side_effect=email_side_effect)
                lambda_params.lambda_update(
                    [], argparse.Namespace(update_deployed=False, dry_run=False, force=True, quiet=True)
                )
                sm.get_secret_value = mock.MagicMock(side_effect=email_side_effect)
                lambda_params.lambda_update(
                    [], argparse.Namespace(update_deployed=True, dry_run=False, force=True, quiet=True)
                )

        with self.subTest("Unset lambda parameters"):
            with mock.patch("dss.operations.lambda_params.ssm_client") as ssm, \
                    mock.patch("dss.operations.lambda_params.lambda_client") as lam:
                # If this is not a dry run, lambda_set in params.py
                # will update the SSM first, so we mock those first.
                # Before we have set the new test variable for the
                # first time, we will see the old environment.
                ssm.put_parameter = mock.MagicMock(return_value=None)
                # use deepcopy here to prevent delete operation from being permanent
                ssm.get_parameter = mock.MagicMock(return_value=copy.deepcopy(ssm_new_env))

                # The lambda_set func in params.py will update lambdas,
                # so we mock the calls that those will make too.
                lam.get_function = mock.MagicMock(return_value=None)
                # use side effect here, and copy the environment for each lambda, so that deletes won't be permanent
                lam.get_function_configuration = mock.MagicMock(
                    side_effect=[copy.deepcopy(lam_new_env) for j in get_deployed_lambdas()]
                )
                lam.update_function_configuration = mock.MagicMock(return_value=None)

                lambda_params.lambda_unset([], argparse.Namespace(name=testvar_name, dry_run=True, quiet=True))
                lambda_params.lambda_unset([], argparse.Namespace(name=testvar_name, dry_run=False, quiet=True))

    def test_events_operations_journal(self):
        with self.subTest("Should forward to lambda when `starting_journal_id` is `None`"):
            self._test_events_operations_journal(None, 0, 2)

        with self.subTest("Should execute journaling when `starting_journal_id` is not `None`"):
            self._test_events_operations_journal("blah", 1, 0)

    def _test_events_operations_journal(self,
                                        starting_journal_id: str,
                                        expected_journal_flashflood_calls: int,
                                        expected_sqs_messenger_calls: int):
        sqs_messenger = mock.MagicMock()
        with mock.patch("dss.operations.events.SQSMessenger", return_value=sqs_messenger), \
                mock.patch("dss.operations.events.list_new_flashflood_journals"), \
                mock.patch("dss.operations.events.journal_flashflood") as journal_flashflood, \
                mock.patch("dss.operations.events.monitor_logs"):
            args = argparse.Namespace(prefix="pfx",
                                      number_of_events=5,
                                      starting_journal_id=starting_journal_id,
                                      job_id=None)
            events.journal([], args)
            self.assertEqual(expected_journal_flashflood_calls, len(journal_flashflood.mock_calls))
            self.assertEqual(expected_sqs_messenger_calls, len(sqs_messenger.mock_calls))

    def _wrap_ssm_env(self, e):
        """
        Package up the SSM environment the way AWS returns it.
        :param dict e: the dict containing the environment to package up and send to SSM store at
            $DSS_DEPLOYMENT_STAGE/environment.
        """
        # Value should be serialized JSON
        ssm_e = {"Parameter": {"Name": "environment", "Value": json.dumps(e)}}
        return ssm_e

    def _wrap_lambda_env(self, e):
        """
        Package up the lambda environment (a.k.a. function configuration) the way AWS returns it.
        :param dict e: the dict containing the lambda function's environment variables
        """
        # Value should be a dict (NOT a string)
        lam_e = {"Environment": {"Variables": e}}
        return lam_e

    def _wrap_secret(self, val):
        """
        Package up the secret the way AWS returns it.
        """
        return {"SecretString": val}


@testmode.integration
class TestOperationsIntegration(TestBundleApiMixin):
    @classmethod
    def setUpClass(cls):
        cls.app = ThreadedLocalServer()
        cls.app.start()

    @classmethod
    def tearDownClass(cls):
        cls.app.shutdown()

    def setUp(self):
        Config.set_config(BucketConfig.TEST)
        self.s3_test_bucket = get_env("DSS_S3_BUCKET_TEST")
        self.gs_test_bucket = get_env("DSS_GS_BUCKET_TEST")
        self.s3_test_fixtures_bucket = get_env("DSS_S3_BUCKET_TEST_FIXTURES")
        self.gs_test_fixtures_bucket = get_env("DSS_GS_BUCKET_TEST_FIXTURES")

    def test_checkout_operations(self):
        with override_bucket_config(BucketConfig.TEST):
            for replica, fixture_bucket in [(Replica['aws'],
                                             self.s3_test_fixtures_bucket),
                                            (Replica['gcp'],
                                             self.gs_test_fixtures_bucket)]:
                bundle, bundle_uuid = self._create_bundle(replica, fixture_bucket)
                args = argparse.Namespace(replica=replica.name, keys=[f'bundles/{bundle_uuid}.{bundle["version"]}'])
                checkout_status = checkout.Verify([], args).process_keys()
                for key in args.keys:
                    self.assertIn(key, checkout_status)
                checkout.Remove([], args).process_keys()
                checkout_status = checkout.Verify([], args).process_keys()
                for key in args.keys:
                    for file in checkout_status[key]:
                        self.assertIs(False, file['bundle_checkout'])
                        self.assertIs(False, file['blob_checkout'])
                checkout.Add([], args).process_keys()
                checkout_status = checkout.Verify([], args).process_keys()
                for key in args.keys:
                    for file in checkout_status[key]:
                        self.assertIs(True, file['bundle_checkout'])
                        self.assertIs(True, file['blob_checkout'])
                self.delete_bundle(replica, bundle_uuid)

    def _create_bundle(self, replica: Replica, fixtures_bucket: str):
        schema = replica.storage_schema
        bundle_uuid = str(uuid.uuid4())
        file_uuid = str(uuid.uuid4())
        resp_obj = self.upload_file_wait(
            f"{schema}://{fixtures_bucket}/test_good_source_data/0",
            replica,
            file_uuid,
            bundle_uuid=bundle_uuid,
        )
        file_version = resp_obj.json['version']
        bundle_version = datetime_to_version_format(datetime.datetime.utcnow())
        resp_obj = self.put_bundle(replica,
                                   bundle_uuid,
                                   [(file_uuid, file_version, "LICENSE")],
                                   bundle_version)
        return resp_obj.json, bundle_uuid


@testmode.integration
class TestSecretsChecker(unittest.TestCase):
    """Test the SecretsChecker class defined in dss/operations/secrets.py"""
    @skip_on_travis
    def test_check_secrets(self):
        """Check that the current stage's secrets conform to expected values"""
        secrets.check_secrets([], argparse.Namespace())

    @skip_on_travis
    def test_custom_stage_secrets(self):
        """
        The SecretsChecker should not test stages that are not in the list:
        dev, staging, integration, prod.
        """
        s = SecretsChecker(stage='somenonsensenamelikeprod')
        s.run()

    @skip_on_travis
    def test_invalid_secrets(self):
        """Check that a ValueError is raised when an unqualified email is stored in a secret."""
        s = SecretsChecker(stage='dev')
        # Override the email field obtained from terraform
        s.email = ['nonsense']
        with self.assertRaises(ValueError):
            s.run()


@testmode.integration
class TestFlacTableOperations(unittest.TestCase):
    """
    Test the dynamodb table with flac operations, tests with actual deployed infra
    """
    file_keys = [f'files/{uuid.uuid4()}.{datetime_to_version_format(datetime.datetime.now())}' for x in range(4)]
    bundle_keys = [f'bundles/{uuid.uuid4()}.{datetime_to_version_format(datetime.datetime.now())}' for x in range(1)]
    all_keys = file_keys + bundle_keys
    groups = ["operations", "testing"]

    def test_flac_flow(self):
        self._test_upload_keys()
        self._test_get_keys(self.all_keys, self.groups)
        self._test_modify_key()
        self._test_remove_keys()

    def _test_upload_keys(self):
        args = argparse.Namespace(keys=self.all_keys,
                                  groups=self.groups)
        resp = flac.Add([], args).process_keys()
        for item in resp:
            self._assert_obj(item, self._build_response_obj(item['key'], self.groups))

    def _test_modify_key(self):
        mod_groups = ["modify"]
        mod_key = [self.all_keys[random.randint(0, len(self.all_keys) - 1)]]
        args = argparse.Namespace(keys=mod_key,
                                  groups=mod_groups)
        resp = flac.Add([], args).process_keys()
        for item in resp:
            self._assert_obj(item, self._build_response_obj(mod_key[0], mod_groups))

    def _test_remove_keys(self):
        args = argparse.Namespace(keys=self.all_keys)
        flac.Remove([], args).process_keys()
        resp = flac.Get([], args).process_keys()
        for item in resp:
            self.assertEqual(item['inDatabase'], False)

    def _test_get_keys(self, keys: list, groups: list):
        args = argparse.Namespace(keys=keys)
        resp = flac.Get([], args).process_keys()
        for item in resp:
            self._assert_obj(item, self._build_response_obj(item['key'], groups))

    def _assert_obj(self, first: dict, second: dict):
        """
        Asserts that two dictionaries are equal, ensures that data types are checked correctly.
        :param first:
        :param second:
        """
        for k, v in first.items():
            self.assertIn(k, second)
            if type(v) is list:
                self.assertListEqual(sorted(v), sorted(second[k]))
            elif type(v) is dict:
                self.assertDictEqual(v, second[k])
            else:
                self.assertEqual(v, second[k])

    def _build_response_obj(self, key: str, groups: list = None, ddb_status: bool = True):
        temp: typing.Dict[typing.Any, typing.Any] = dict()
        temp['key'] = key
        temp['uuid'] = UUID_REGEX.search(key).group(0)
        temp['inDatabase'] = ddb_status
        if groups:
            temp['groups'] = groups
        return temp


if __name__ == '__main__':
    unittest.main()
