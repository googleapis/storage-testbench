#!/usr/bin/env python3
#
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit test for testbench.grpc."""

import collections
import datetime
import json
import os
import time
import unittest
import unittest.mock

import crc32c
import grpc
import grpc_status
from google.protobuf import field_mask_pb2, timestamp_pb2

import gcs
import testbench
from google.iam.v1 import iam_policy_pb2, policy_pb2
from google.storage.v2 import storage_pb2, storage_pb2_grpc


class TestGrpc(unittest.TestCase):
    def mock_context(self):
        context = unittest.mock.Mock()
        context.invocation_metadata = unittest.mock.Mock(return_value=dict())
        return context

    def setUp(self):
        self.db = testbench.database.Database.init()
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket-name"}),
        )
        self.bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.db.insert_bucket(self.bucket, None)
        self.grpc = testbench.grpc_server.StorageServicer(self.db)

    def test_insert_test_bucket(self):
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)
        database = testbench.database.Database.init()
        server = testbench.grpc_server.StorageServicer(database)
        names = {b.metadata.name for b in database.list_bucket("", "", None)}
        self.assertEqual(names, set())

        os.environ["GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME"] = "test-bucket-1"
        database = testbench.database.Database.init()
        server = testbench.grpc_server.StorageServicer(database)
        names = {b.metadata.name for b in database.list_bucket("", "", None)}
        self.assertIn("projects/_/buckets/test-bucket-1", names)

    def test_delete_bucket(self):
        # Verify the bucket can be found using REST
        b = self.db.get_bucket("bucket-name", context=None)
        self.assertIsNotNone(b)
        # Delete the bucket using gRPC
        context = unittest.mock.Mock()
        _ = self.grpc.DeleteBucket(
            storage_pb2.DeleteBucketRequest(name="projects/_/buckets/bucket-name"),
            context,
        )
        # Verify the bucket is deleted
        with self.assertRaises(testbench.error.RestException) as rest:
            _ = self.db.get_bucket("bucket-name", context=None)
        self.assertEqual(rest.exception.code, 404)

    def test_get_bucket(self):
        context = unittest.mock.Mock()
        response = self.grpc.GetBucket(
            storage_pb2.GetBucketRequest(name="projects/_/buckets/bucket-name"), context
        )
        self.assertEqual(response.name, "projects/_/buckets/bucket-name")
        self.assertEqual(response.bucket_id, "bucket-name")
        self.assertEqual(response, self.bucket.metadata)

    def test_create_bucket(self):
        request = storage_pb2.CreateBucketRequest(
            parent="projects/test-project",
            bucket_id="test-bucket-name",
            bucket=storage_pb2.Bucket(),
        )
        context = unittest.mock.Mock()
        response = self.grpc.CreateBucket(request, context)
        self.assertEqual(response.name, "projects/_/buckets/test-bucket-name")
        self.assertEqual(response.bucket_id, "test-bucket-name")
        self.assertTrue(response.project.startswith("projects/"))

    def test_create_bucket_predefined_acls(self):
        acls = [
            "authenticatedRead",
            "projectPrivate",
            "private",
            "publicRead",
            "publicReadWrite",
            "",
        ]
        for i, acl in enumerate(acls):
            id = "test-bucket-name-%d" % i
            request = storage_pb2.CreateBucketRequest(
                parent="projects/test-project",
                bucket_id=id,
                bucket=storage_pb2.Bucket(),
                predefined_acl=acl,
            )
            context = unittest.mock.Mock()
            response = self.grpc.CreateBucket(request, context)
            self.assertEqual(response.bucket_id, id)
            self.assertNotEqual(len(response.acl), 0, msg=response)

    def test_create_bucket_predefined_default_object_acls(self):
        acls = [
            "authenticatedRead",
            "bucketOwnerFullControl",
            "bucketOwnerRead",
            "projectPrivate",
            "private",
            "publicRead",
            "",
        ]
        for i, acl in enumerate(acls):
            id = "test-bucket-name-%d" % i
            request = storage_pb2.CreateBucketRequest(
                parent="projects/test-project",
                bucket_id=id,
                bucket=storage_pb2.Bucket(),
                predefined_default_object_acl=acl,
            )
            context = unittest.mock.Mock()
            response = self.grpc.CreateBucket(request, context)
            self.assertEqual(response.bucket_id, id)
            self.assertNotEqual(len(response.default_object_acl), 0, msg=response)

    def test_list_buckets(self):
        ids = ["bucket-3", "bucket-2", "bucket-1"]
        for id in ids:
            context = unittest.mock.Mock()
            response = self.grpc.CreateBucket(
                storage_pb2.CreateBucketRequest(
                    parent="projects/test-project",
                    bucket_id=id,
                    bucket=storage_pb2.Bucket(),
                ),
                context,
            )
            context.abort.assert_not_called()
            self.assertEqual(response.bucket_id, id)
        context = unittest.mock.Mock()
        response = self.grpc.ListBuckets(
            storage_pb2.ListBucketsRequest(parent="projects/test-project"), context
        )
        context.assert_not_called()
        expected = {("projects/_/buckets/" + id) for id in ids}
        actual = {b.name for b in response.buckets}
        self.assertEqual(actual, actual | expected)
        for b in response.buckets:
            self.assertFalse(b.HasField("owner"), msg=b)
            self.assertEqual(len(b.acl), 0, msg=b)
            self.assertEqual(len(b.default_object_acl), 0, msg=b)

    def test_list_buckets_all(self):
        ids = ["bucket-3", "bucket-2", "bucket-1"]
        for id in ids:
            context = unittest.mock.Mock()
            response = self.grpc.CreateBucket(
                storage_pb2.CreateBucketRequest(
                    parent="projects/test-project",
                    bucket_id=id,
                    bucket=storage_pb2.Bucket(),
                ),
                context,
            )
            context.abort.assert_not_called()
            self.assertEqual(response.bucket_id, id)
        context = unittest.mock.Mock()
        response = self.grpc.ListBuckets(
            storage_pb2.ListBucketsRequest(
                parent="projects/test-project",
                read_mask=field_mask_pb2.FieldMask(paths=["*"]),
            ),
            context,
        )
        context.assert_not_called()
        expected = {("projects/_/buckets/" + id) for id in ids}
        actual = {b.name for b in response.buckets}
        self.assertEqual(actual, actual | expected)
        for b in response.buckets:
            self.assertTrue(b.HasField("owner"), msg=b)
            self.assertNotEqual(len(b.acl), 0, msg=b)
            self.assertNotEqual(len(b.default_object_acl), 0, msg=b)

    def test_list_buckets_filter(self):
        ids = ["bucket-3", "bucket-2", "bucket-1"]
        for id in ids:
            context = unittest.mock.Mock()
            response = self.grpc.CreateBucket(
                storage_pb2.CreateBucketRequest(
                    parent="projects/test-project",
                    bucket_id=id,
                    bucket=storage_pb2.Bucket(),
                ),
                context,
            )
            context.abort.assert_not_called()
            self.assertEqual(response.bucket_id, id)
        context = unittest.mock.Mock()
        response = self.grpc.ListBuckets(
            storage_pb2.ListBucketsRequest(
                parent="projects/test-project",
                read_mask=field_mask_pb2.FieldMask(paths=["name", "owner", "acl"]),
            ),
            context,
        )
        context.assert_not_called()
        expected = {("projects/_/buckets/" + id) for id in ids}
        actual = {b.name for b in response.buckets}
        self.assertEqual(actual, actual | expected)
        for b in response.buckets:
            self.assertTrue(b.HasField("owner"), msg=b)
            self.assertNotEqual(len(b.acl), 0, msg=b)

    def test_list_buckets_prefix(self):
        ids = ["a-bucket-3", "b-bucket-2", "a-bucket-1"]
        for id in ids:
            context = unittest.mock.Mock()
            response = self.grpc.CreateBucket(
                storage_pb2.CreateBucketRequest(
                    parent="projects/test-project",
                    bucket_id=id,
                    bucket=storage_pb2.Bucket(),
                ),
                context,
            )
            context.abort.assert_not_called()
            self.assertEqual(response.bucket_id, id)
        context = unittest.mock.Mock()
        response = self.grpc.ListBuckets(
            storage_pb2.ListBucketsRequest(parent="projects/test-project", prefix="a-"),
            context,
        )
        context.assert_not_called()
        want = [ids[0], ids[2]]
        expected = {("projects/_/buckets/" + id) for id in want}
        actual = {b.name for b in response.buckets}
        self.assertEqual(actual, actual | expected)
        for b in response.buckets:
            self.assertFalse(b.HasField("owner"), msg=b)
            self.assertEqual(len(b.acl), 0, msg=b)
            self.assertEqual(len(b.default_object_acl), 0, msg=b)

    def test_list_buckets_failure(self):
        context = unittest.mock.Mock()
        _ = self.grpc.ListBuckets(
            storage_pb2.ListBucketsRequest(parent="test-invalid-format"), context
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_lock_bucket_retention_policy(self):
        self.assertFalse(self.bucket.metadata.retention_policy.is_locked)

        context = unittest.mock.Mock()
        response = self.grpc.LockBucketRetentionPolicy(
            storage_pb2.LockBucketRetentionPolicyRequest(
                bucket="projects/_/buckets/bucket-name",
                if_metageneration_match=self.bucket.metadata.metageneration,
            ),
            context,
        )
        self.assertEqual(response.name, "projects/_/buckets/bucket-name")
        self.assertEqual(response.bucket_id, "bucket-name")
        self.assertEqual(response, self.bucket.metadata)
        self.assertTrue(response.retention_policy.is_locked)

    def test_lock_bucket_retention_policy_invalid_preconditions(self):
        context = unittest.mock.Mock()
        _ = self.grpc.LockBucketRetentionPolicy(
            storage_pb2.LockBucketRetentionPolicyRequest(
                bucket="projects/_/buckets/bucket-name",
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

        context = unittest.mock.Mock()
        _ = self.grpc.LockBucketRetentionPolicy(
            storage_pb2.LockBucketRetentionPolicyRequest(
                bucket="projects/_/buckets/bucket-name",
                if_metageneration_match=0,
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

        context = unittest.mock.Mock()
        _ = self.grpc.LockBucketRetentionPolicy(
            storage_pb2.LockBucketRetentionPolicyRequest(
                bucket="projects/_/buckets/bucket-name",
                if_metageneration_match=-42,
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_lock_bucket_retention_policy_fails_precondition(self):
        context = unittest.mock.Mock()
        # The code depends on `context.abort()` raising an exception.
        context.abort = unittest.mock.MagicMock()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            _ = self.grpc.LockBucketRetentionPolicy(
                storage_pb2.LockBucketRetentionPolicyRequest(
                    bucket="projects/_/buckets/bucket-name",
                    # Use a valid, but not matching pre-condition
                    if_metageneration_match=self.bucket.metadata.metageneration + 1,
                ),
                context,
            )
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_get_iam_policy(self):
        context = unittest.mock.Mock()
        response = self.grpc.GetIamPolicy(
            iam_policy_pb2.GetIamPolicyRequest(
                resource="projects/_/buckets/bucket-name"
            ),
            context,
        )
        self.assertEqual(
            sorted([b.role for b in response.bindings]),
            [
                "roles/storage.legacyBucketOwner",
                "roles/storage.legacyBucketReader",
                "roles/storage.legacyBucketWriter",
            ],
        )

    def test_set_iam_policy(self):
        context = unittest.mock.Mock()
        get = self.grpc.GetIamPolicy(
            iam_policy_pb2.GetIamPolicyRequest(
                resource="projects/_/buckets/bucket-name"
            ),
            context,
        )
        get_etag = bytes(get.etag)
        policy = policy_pb2.Policy()
        policy.CopyFrom(get)
        policy.bindings.append(
            policy_pb2.Binding(
                role="role/storage.admin", members=["user:not-a-user@example.com"]
            )
        )

        context = unittest.mock.Mock()
        set = self.grpc.SetIamPolicy(
            iam_policy_pb2.SetIamPolicyRequest(
                resource="projects/_/buckets/bucket-name", policy=policy
            ),
            context,
        )
        # Ignore the ETag field when comparing results
        policy.etag = set.etag
        self.assertEqual(set, policy)

        # A second set with the old ETag should fail.
        context = unittest.mock.Mock()
        policy.etag = get_etag
        _ = self.grpc.SetIamPolicy(
            iam_policy_pb2.SetIamPolicyRequest(
                resource="projects/_/buckets/bucket-name", policy=policy
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_test_iam_permissions(self):
        context = unittest.mock.Mock()
        permissions = {
            "storage.buckets.create",
            "storage.objects.create",
            "not-storage.thing.get",
        }
        response = self.grpc.TestIamPermissions(
            iam_policy_pb2.TestIamPermissionsRequest(
                resource="projects/_/buckets/bucket-name",
                permissions=permissions,
            ),
            context,
        )
        self.assertEqual(
            set(response.permissions),
            permissions,
        )

    def test_update_bucket(self):
        # First check the default bucket state.
        context = unittest.mock.Mock()
        get = self.grpc.GetBucket(
            storage_pb2.GetBucketRequest(name="projects/_/buckets/bucket-name"), context
        )
        self.assertEqual("projects/_/buckets/bucket-name", get.name)
        self.assertEqual(dict(), get.labels)
        self.assertEqual("STANDARD", get.storage_class)
        self.assertEqual("DEFAULT", get.rpo)
        metageneration = get.metageneration

        # Then change some properties, note that we set some attributes but not the
        # corresponding field mask, those should not change.
        context = unittest.mock.Mock()
        request = storage_pb2.UpdateBucketRequest(
            bucket=storage_pb2.Bucket(
                name="projects/_/buckets/bucket-name",
                labels={"key": "value"},
                storage_class="NEARLINE",
                rpo="ASYNC_TURBO",
                acl=get.acl,
                default_object_acl=get.default_object_acl,
            ),
            update_mask=field_mask_pb2.FieldMask(
                paths=["labels", "rpo", "acl", "default_object_acl"]
            ),
        )
        response = self.grpc.UpdateBucket(request, context)
        self.assertEqual("projects/_/buckets/bucket-name", response.name)
        self.assertEqual({"key": "value"}, response.labels)
        self.assertEqual("STANDARD", response.storage_class)
        self.assertEqual("ASYNC_TURBO", response.rpo)
        self.assertLess(metageneration, response.metageneration)

        # Finally verify the changes are persisted
        context = unittest.mock.Mock()
        get = self.grpc.GetBucket(
            storage_pb2.GetBucketRequest(name="projects/_/buckets/bucket-name"), context
        )
        self.assertEqual("projects/_/buckets/bucket-name", get.name)
        self.assertEqual({"key": "value"}, get.labels)
        self.assertEqual("STANDARD", get.storage_class)
        self.assertEqual("ASYNC_TURBO", get.rpo)

    def test_update_bucket_invalid_masks(self):
        for invalid in [
            "name",
            "bucket_id",
            "project",
            "metageneration",
            "location",
            "location_type",
            "create_time",
            "update_time",
            "owner",
            "not-a-valid-field",
        ]:
            context = unittest.mock.Mock()
            _ = self.grpc.UpdateBucket(
                storage_pb2.UpdateBucketRequest(
                    bucket=storage_pb2.Bucket(name="projects/_/buckets/bucket-name"),
                    update_mask=field_mask_pb2.FieldMask(paths=[invalid]),
                ),
                context,
            )
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )

    def test_update_bucket_autoclass(self):
        context = unittest.mock.Mock()
        get = self.grpc.GetBucket(
            storage_pb2.GetBucketRequest(name="projects/_/buckets/bucket-name"), context
        )
        metageneration = get.metageneration

        # Change the autoclass.
        context = unittest.mock.Mock()
        request = storage_pb2.UpdateBucketRequest(
            bucket=storage_pb2.Bucket(
                name="projects/_/buckets/bucket-name",
                autoclass=storage_pb2.Bucket.Autoclass(enabled=True),
            ),
            update_mask=field_mask_pb2.FieldMask(paths=["autoclass"]),
        )
        response = self.grpc.UpdateBucket(request, context)
        self.assertEqual("projects/_/buckets/bucket-name", response.name)
        self.assertEqual(True, response.autoclass.enabled)
        self.assertEqual(response.update_time, response.autoclass.toggle_time)
        self.assertLess(metageneration, response.metageneration)

    def test_update_bucket_labels(self):
        request = storage_pb2.CreateBucketRequest(
            parent="projects/test-project",
            bucket_id="test-bucket-name",
            bucket=storage_pb2.Bucket(labels={"k0": "v0", "k1": "v1", "k2": "v2"}),
        )
        context = unittest.mock.Mock()
        response = self.grpc.CreateBucket(request, context)
        self.assertEqual(response.labels, {"k0": "v0", "k1": "v1", "k2": "v2"})

        # Change the value of a label, remove one label, leave one label unchanged,
        # and insert a new label
        request = storage_pb2.UpdateBucketRequest(
            bucket=storage_pb2.Bucket(
                name="projects/_/buckets/test-bucket-name",
                labels={"k0": "new-v0", "k3": "v3"},
            ),
            update_mask=field_mask_pb2.FieldMask(
                paths=["labels.k0", "labels.k1", "labels.k3"]
            ),
        )
        context = unittest.mock.Mock()
        response = self.grpc.UpdateBucket(request, context)
        self.assertEqual(response.labels, {"k0": "new-v0", "k2": "v2", "k3": "v3"})

        # Finally verify the changes are persisted
        context = unittest.mock.Mock()
        get = self.grpc.GetBucket(
            storage_pb2.GetBucketRequest(name="projects/_/buckets/test-bucket-name"),
            context,
        )
        self.assertEqual(get.labels, {"k0": "new-v0", "k2": "v2", "k3": "v3"})

    def test_update_bucket_acls(self):
        request = storage_pb2.CreateBucketRequest(
            parent="projects/test-project",
            bucket_id="test-bucket-name",
            bucket=storage_pb2.Bucket(),
        )
        context = unittest.mock.Mock()
        response = self.grpc.CreateBucket(request, context)
        context.abort.assert_not_called()

        new_acl = list(response.acl)
        new_acl.append(
            storage_pb2.BucketAccessControl(
                entity="serviceAccount:fake-sa@fake-project.example.com",
                role="READER",
            )
        )
        new_default_object_acl = list(response.default_object_acl)
        new_default_object_acl.append(
            storage_pb2.ObjectAccessControl(
                entity="allAuthenticatedUsers",
                role="READER",
            )
        )
        request = storage_pb2.UpdateBucketRequest(
            bucket=storage_pb2.Bucket(
                name="projects/_/buckets/test-bucket-name",
                acl=list(new_acl),
                default_object_acl=list(new_default_object_acl),
            ),
            if_metageneration_match=response.metageneration,
            update_mask=field_mask_pb2.FieldMask(paths=["acl", "default_object_acl"]),
        )
        context = unittest.mock.Mock()
        response = self.grpc.UpdateBucket(request, context)
        context.abort.assert_not_called()
        self.assertEqual(response.acl, new_acl)
        self.assertEqual(response.default_object_acl, new_default_object_acl)

    def test_update_bucket_soft_delete(self):
        policy = storage_pb2.Bucket.SoftDeletePolicy()
        policy.retention_duration.FromTimedelta(datetime.timedelta(seconds=30 * 86400))
        request = storage_pb2.CreateBucketRequest(
            parent="projects/test-project",
            bucket_id="test-bucket-name",
            bucket=storage_pb2.Bucket(soft_delete_policy=policy),
        )
        context = unittest.mock.Mock()
        response = self.grpc.CreateBucket(request, context)
        context.abort.assert_not_called()
        self.assertEqual(
            response.soft_delete_policy.retention_duration, policy.retention_duration
        )
        self.assertNotEqual(
            response.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

        policy = storage_pb2.Bucket.SoftDeletePolicy()
        policy.retention_duration.FromTimedelta(datetime.timedelta(seconds=60 * 86400))
        request = storage_pb2.UpdateBucketRequest(
            bucket=storage_pb2.Bucket(
                name="projects/_/buckets/test-bucket-name",
                soft_delete_policy=policy,
            ),
            if_metageneration_match=response.metageneration,
            update_mask=field_mask_pb2.FieldMask(paths=["soft_delete_policy"]),
        )
        context = unittest.mock.Mock()
        response = self.grpc.UpdateBucket(request, context)
        context.abort.assert_not_called()
        self.assertEqual(
            response.soft_delete_policy.retention_duration, policy.retention_duration
        )
        self.assertNotEqual(
            response.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

        policy = storage_pb2.Bucket.SoftDeletePolicy()
        policy.retention_duration.FromTimedelta(
            datetime.timedelta(seconds=30 * 86400, milliseconds=500)
        )
        request = storage_pb2.UpdateBucketRequest(
            bucket=storage_pb2.Bucket(
                name="projects/_/buckets/test-bucket-name",
                soft_delete_policy=policy,
            ),
            if_metageneration_match=response.metageneration,
            update_mask=field_mask_pb2.FieldMask(paths=["soft_delete_policy"]),
        )
        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            _ = self.grpc.UpdateBucket(request, context)
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_delete_notification(self):
        context = unittest.mock.Mock()
        create = self.grpc.CreateNotificationConfig(
            storage_pb2.CreateNotificationConfigRequest(
                parent="projects/_/buckets/bucket-name",
                notification_config=storage_pb2.NotificationConfig(
                    topic="//pubsub.googleapis.com/projects/test-project-id/topics/test-topic",
                    custom_attributes={"key": "value"},
                    payload_format="JSON_API_V1",
                ),
            ),
            context,
        )
        self.assertTrue(
            create.name.startswith(
                "projects/_/buckets/bucket-name/notificationConfigs/"
            ),
            msg=create,
        )

        context = unittest.mock.Mock()
        _ = self.grpc.DeleteNotificationConfig(
            storage_pb2.GetNotificationConfigRequest(name=create.name), context
        )
        context.abort.assert_not_called()

        # The code depends on `context.abort()` raising an exception.
        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            _ = self.grpc.GetNotificationConfig(
                storage_pb2.GetNotificationConfigRequest(name=create.name), context
            )
        context.abort.assert_called_once_with(
            grpc.StatusCode.NOT_FOUND, unittest.mock.ANY
        )

    def test_delete_notification_malformed(self):
        context = unittest.mock.Mock()
        _ = self.grpc.DeleteNotificationConfig(
            storage_pb2.GetNotificationConfigRequest(name=""), context
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_get_notification(self):
        context = unittest.mock.Mock()
        topic_name = (
            "//pubsub.googleapis.com/projects/test-project-id/topics/test-topic"
        )
        response = self.grpc.CreateNotificationConfig(
            storage_pb2.CreateNotificationConfigRequest(
                parent="projects/_/buckets/bucket-name",
                notification_config=storage_pb2.NotificationConfig(
                    topic=topic_name,
                    custom_attributes={"key": "value"},
                    payload_format="JSON_API_V1",
                ),
            ),
            context,
        )
        self.assertTrue(
            response.name.startswith(
                "projects/_/buckets/bucket-name/notificationConfigs/"
            ),
            msg=response,
        )

        context = unittest.mock.Mock()
        get = self.grpc.GetNotificationConfig(
            storage_pb2.GetNotificationConfigRequest(name=response.name), context
        )
        self.assertEqual(get, response)
        self.assertEqual(get.topic, topic_name)

    def test_get_notification_malformed(self):
        context = unittest.mock.Mock()
        _ = self.grpc.GetNotificationConfig(
            storage_pb2.GetNotificationConfigRequest(
                name="projects/_/buckets/bucket-name/"
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_create_notification(self):
        topic_name = (
            "//pubsub.googleapis.com/projects/test-project-id/topics/test-topic"
        )
        context = unittest.mock.Mock()
        response = self.grpc.CreateNotificationConfig(
            storage_pb2.CreateNotificationConfigRequest(
                parent="projects/_/buckets/bucket-name",
                notification_config=storage_pb2.NotificationConfig(
                    topic=topic_name,
                    custom_attributes={"key": "value"},
                    payload_format="JSON_API_V1",
                ),
            ),
            context,
        )
        self.assertTrue(
            response.name.startswith(
                "projects/_/buckets/bucket-name/notificationConfigs/"
            ),
            msg=response,
        )
        self.assertEqual(response.topic, topic_name)

        # Invalid topic names return an error
        invalid_topic_names = [
            "",
            "//pubsub.googleapis.com",
            "//pubsub.googleapis.com/",
            "//pubsub.googleapis.com/projects",
            "//pubsub.googleapis.com/projects/",
            "//pubsub.googleapis.com/projects/test-project-id",
            "//pubsub.googleapis.com/projects/test-project-id/",
            "//pubsub.googleapis.com/projects/test-project-id/topics",
            "//pubsub.googleapis.com/projects/test-project-id/topics/",
        ]
        for topic in invalid_topic_names:
            context = unittest.mock.Mock()
            context.abort = unittest.mock.MagicMock()
            context.abort.side_effect = grpc.RpcError()
            with self.assertRaises(grpc.RpcError):
                _ = self.grpc.CreateNotificationConfig(
                    storage_pb2.CreateNotificationConfigRequest(
                        parent="projects/_/buckets/bucket-name",
                        notification_config=storage_pb2.NotificationConfig(
                            topic=topic, payload_format="JSON_API_V1"
                        ),
                    ),
                    context,
                )
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )

    def test_list_notifications(self):
        expected = set()
        topics = [
            "//pubsub.googleapis.com/projects/test-project-id/topics/test-topic-1",
            "//pubsub.googleapis.com/projects/test-project-id/topics/test-topic-2",
        ]
        for topic in topics:
            context = unittest.mock.Mock()
            response = self.grpc.CreateNotificationConfig(
                storage_pb2.CreateNotificationConfigRequest(
                    parent="projects/_/buckets/bucket-name",
                    notification_config=storage_pb2.NotificationConfig(
                        topic=topic,
                        custom_attributes={"key": "value"},
                        payload_format="JSON_API_V1",
                    ),
                ),
                context,
            )
            expected.add(response.name)

        context = unittest.mock.Mock()
        response = self.grpc.ListNotificationConfigs(
            storage_pb2.ListNotificationConfigsRequest(
                parent="projects/_/buckets/bucket-name"
            ),
            context,
        )
        names = {n.name for n in response.notification_configs}
        self.assertEqual(names, expected)

    def test_compose_object(self):
        payloads = {
            "fox": b"The quick brown fox jumps over the lazy dog\n",
            "zebra": b"How vexingly quick daft zebras jump!\n",
        }
        source_objects = []
        for name, media in payloads.items():
            request = testbench.common.FakeRequest(
                args={"name": name}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object("bucket-name", blob, None)
            source_objects.append(
                storage_pb2.ComposeObjectRequest.SourceObject(
                    name=name,
                    generation=blob.metadata.generation,
                )
            )
        context = unittest.mock.Mock()
        context.invocation_metadata = unittest.mock.MagicMock(return_value=dict())
        response = self.grpc.ComposeObject(
            storage_pb2.ComposeObjectRequest(
                destination=storage_pb2.Object(
                    name="composed-object-name", bucket="projects/_/buckets/bucket-name"
                ),
                source_objects=source_objects,
            ),
            context,
        )
        expected_media = b"".join([p for _, p in payloads.items()])
        self.assertEqual(response.size, len(expected_media))

        # Verify the newly created object has the right contents
        context = unittest.mock.Mock()
        response = self.grpc.GetObject(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="composed-object-name"
            ),
            context,
        )
        self.assertEqual(response.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(response.name, "composed-object-name")
        self.assertNotEqual(0, response.generation)
        self.assertEqual(response.size, len(expected_media))

    def test_compose_object_bad_inputs(self):
        SourceObject = storage_pb2.ComposeObjectRequest.SourceObject
        test_cases = {
            "missing sources": storage_pb2.ComposeObjectRequest(
                destination=storage_pb2.Object(
                    name="composed-object-name", bucket="projects/_/buckets/bucket-name"
                ),
            ),
            "missing destination.name": storage_pb2.ComposeObjectRequest(
                destination=storage_pb2.Object(
                    name="", bucket="projects/_/buckets/bucket-name"
                ),
                source_objects=[SourceObject(name="zebra")],
            ),
            "missing destination.bucket": storage_pb2.ComposeObjectRequest(
                destination=storage_pb2.Object(name="composed-object-name", bucket=""),
                source_objects=[SourceObject(name="zebra")],
            ),
            "missing source name": storage_pb2.ComposeObjectRequest(
                destination=storage_pb2.Object(
                    name="composed-object-name", bucket="projects/_/buckets/bucket-name"
                ),
                source_objects=[SourceObject(name="")],
            ),
            "too many source objects": storage_pb2.ComposeObjectRequest(
                destination=storage_pb2.Object(
                    name="composed-object-name", bucket="projects/_/buckets/bucket-name"
                ),
                source_objects=[SourceObject(name="zebra")] * 64,
            ),
        }
        for name, request in test_cases.items():
            context = unittest.mock.Mock(name=name)
            context.invocation_metadata = unittest.mock.MagicMock(return_value=dict())
            _ = self.grpc.ComposeObject(request, context)
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )

    def test_compose_object_failed_source_precondition(self):
        payloads = {
            "fox": b"The quick brown fox jumps over the lazy dog\n",
            "zebra": b"How vexingly quick daft zebras jump!\n",
        }
        source_objects = []
        for name, media in payloads.items():
            request = testbench.common.FakeRequest(
                args={"name": name}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object("bucket-name", blob, None)
            source_objects.append(
                storage_pb2.ComposeObjectRequest.SourceObject(
                    name=name,
                    # Use an invalid source object precondition
                    object_preconditions=storage_pb2.ComposeObjectRequest.SourceObject.ObjectPreconditions(
                        if_generation_match=blob.metadata.generation + 10
                    ),
                )
            )
        context = unittest.mock.Mock()
        context.invocation_metadata = unittest.mock.MagicMock(return_value=dict())
        _ = self.grpc.ComposeObject(
            storage_pb2.ComposeObjectRequest(
                destination=storage_pb2.Object(
                    name="composed-object-name", bucket="projects/_/buckets/bucket-name"
                ),
                source_objects=source_objects,
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_delete_object(self):
        media = b"The quick brown fox jumps over the lazy dog"
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, context=None)
        full_bucket_name = blob.metadata.bucket
        context = unittest.mock.Mock()
        _ = self.grpc.DeleteObject(
            storage_pb2.DeleteObjectRequest(
                bucket=full_bucket_name, object="object-name"
            ),
            context,
        )
        context = unittest.mock.Mock()
        items, _ = self.db.list_object(
            storage_pb2.ListObjectsRequest(parent=full_bucket_name),
            full_bucket_name,
            context,
        )
        names = {o.name for o in items}
        self.assertNotIn("object-name", names)

    def test_cancel_resumable_write_not_found(self):
        context = unittest.mock.Mock()
        _ = self.grpc.CancelResumableWrite(
            storage_pb2.CancelResumableWriteRequest(upload_id="test-only-invalid"),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.NOT_FOUND, unittest.mock.ANY
        )

    def test_cancel_resumable_write(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context=self.mock_context(),
        )
        self.assertIsNotNone(start.upload_id)

        context = unittest.mock.Mock()
        _ = self.grpc.CancelResumableWrite(
            storage_pb2.CancelResumableWriteRequest(upload_id=start.upload_id),
            context,
        )
        context.abort.assert_not_called()

    def test_get_object(self):
        media = b"The quick brown fox jumps over the lazy dog"
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)
        context = unittest.mock.Mock()
        response = self.grpc.GetObject(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            context,
        )
        self.assertEqual(response.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(response.name, "object-name")
        self.assertNotEqual(0, response.generation)
        self.assertEqual(response.size, len(media))

    @staticmethod
    def _create_block(desired_bytes):
        line = "A" * 127 + "\n"
        return int(desired_bytes / len(line)) * line

    def test_read_object(self):
        media = TestGrpc._create_block(5 * 1024 * 1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)
        response = self.grpc.ReadObject(
            storage_pb2.ReadObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            "fake-context",
        )
        chunks = [r for r in response]
        for i, c in enumerate(chunks):
            self.assertIsNotNone(c.checksummed_data, msg=i)
            self.assertEqual(
                crc32c.crc32c(c.checksummed_data.content),
                c.checksummed_data.crc32c,
                msg=i,
            )
        expected_sizes = [2 * 1024 * 1024, 2 * 1024 * 1024, 1 * 1024 * 1024]
        self.assertEqual(
            expected_sizes, [len(c.checksummed_data.content) for c in chunks]
        )
        self.assertEqual(
            crc32c.crc32c(media),
            crc32c.crc32c(b"".join([c.checksummed_data.content for c in chunks])),
        )

    def test_read_zero_size_object(self):
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=b"", headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)
        response = self.grpc.ReadObject(
            storage_pb2.ReadObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            "fake-context",
        )
        chunks = [r for r in response]
        self.assertEqual(1, len(chunks))
        c = chunks[0]
        self.assertEqual(0, len(c.checksummed_data.content))
        self.assertEqual(0, c.checksummed_data.crc32c)

    def test_read_object_byte_range(self):
        media = TestGrpc._create_block(5 * 1024 * 1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)
        response = self.grpc.ReadObject(
            storage_pb2.ReadObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                read_offset=1,
                read_limit=10,
            ),
            "fake-context",
        )
        chunks = [r for r in response]
        self.assertEqual(1, len(chunks))
        c = chunks[0]
        self.assertEqual(10, len(c.checksummed_data.content))
        self.assertEqual(
            c.checksummed_data.crc32c, crc32c.crc32c(c.checksummed_data.content)
        )
        self.assertEqual(media[1:11], c.checksummed_data.content)
        self.assertEqual(1, c.content_range.start)
        self.assertEqual(11, c.content_range.end)
        self.assertEqual(len(media), c.content_range.complete_length)

    def test_read_object_read_offset_too_large(self):
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=b"abcd", headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)

        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        context.invocation_metadata = unittest.mock.MagicMock(return_value=dict())
        response = self.grpc.ReadObject(
            storage_pb2.ReadObjectRequest(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                read_offset=10,
            ),
            context,
        )
        chunks = [r for r in response]
        self.assertEqual(0, len(chunks))
        context.abort.assert_called_once()

    def test_update_object(self):
        media = b"How vexingly quick daft zebras jump!"
        request = testbench.common.FakeRequest(
            args={"name": "object-name", "metadata": {"key: value"}},
            data=media,
            headers={},
            environ={},
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        metageneration = blob.metadata.metageneration
        self.db.insert_object("bucket-name", blob, None)
        context = unittest.mock.Mock()
        request = storage_pb2.UpdateObjectRequest(
            object=storage_pb2.Object(
                bucket="projects/_/buckets/bucket-name",
                name="object-name",
                metadata={"key": "value", "new-key": "new-value"},
                content_type="text/plain",
                cache_control="fancy cache",
                acl=blob.metadata.acl,
            ),
            update_mask=field_mask_pb2.FieldMask(paths=["content_type", "metadata"]),
            predefined_acl="publicRead",
        )
        response = self.grpc.UpdateObject(request, context)
        predefined = [
            testbench.acl.get_object_entity("OWNER", None),
            "allUsers",
        ]
        self.assertEqual("text/plain", response.content_type)
        self.assertEqual(response.metadata, {"key": "value", "new-key": "new-value"})
        self.assertEqual("", response.cache_control)
        self.assertListEqual(predefined, [acl.entity for acl in response.acl])
        self.assertLess(metageneration, response.metageneration)

        # Verify the update is "persisted" as opposed to just changing the response
        context = unittest.mock.Mock()
        get = self.grpc.GetObject(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            context,
        )
        self.assertEqual("text/plain", get.content_type)
        self.assertEqual({"key": "value", "new-key": "new-value"}, get.metadata)
        self.assertEqual("", get.cache_control)
        self.assertListEqual(predefined, [acl.entity for acl in get.acl])

    def test_update_object_invalid(self):
        media = b"How vexingly quick daft zebras jump!"
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)
        for invalid in [
            "name",
            "bucket",
            "generation",
            "metageneration",
            "storage_class",
            "size",
            "delete_time",
            "create_time",
            "component_count",
            "checksums",
            "update_time",
            "kms_key",
            "update_storage_class_time",
            "owner",
            "customer_encryption",
            "not-a-valid-field",
        ]:
            context = unittest.mock.Mock(name="testing with path=" + invalid)
            _ = self.grpc.UpdateObject(
                storage_pb2.UpdateObjectRequest(
                    object=storage_pb2.Object(
                        bucket="projects/_/buckets/bucket-name",
                        name="object-name",
                    ),
                    update_mask=field_mask_pb2.FieldMask(paths=[invalid]),
                ),
                context,
            )
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )

    def test_update_object_metadata(self):
        media = b"How vexingly quick daft zebras jump!"
        request = testbench.common.FakeRequest(
            args={"name": "object-name"},
            data=media,
            headers={},
            environ={},
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)
        blob.metadata.metadata.update({"k0": "v0", "k1": "v1", "k2": "v2"})
        # Change the value of a metadata pair, remove one metadata pai, leave
        # one unchanged, and insert a new metadata pair.
        request = storage_pb2.UpdateObjectRequest(
            object=storage_pb2.Object(
                bucket="projects/_/buckets/bucket-name",
                name="object-name",
                metadata={"k0": "new-v0", "k3": "v3"},
            ),
            update_mask=field_mask_pb2.FieldMask(
                paths=["metadata.k0", "metadata.k1", "metadata.k3"]
            ),
        )
        context = unittest.mock.Mock()
        response = self.grpc.UpdateObject(request, context)
        expected = {"k0": "new-v0", "k2": "v2", "k3": "v3"}
        self.assertEqual(response.metadata, {**response.metadata, **expected})

        # Finally verify the changes are persisted
        context = unittest.mock.Mock()
        response = self.grpc.GetObject(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            context,
        )
        self.assertEqual(response.metadata, {**response.metadata, **expected})

    def test_update_object_acl(self):
        media = b"How vexingly quick daft zebras jump!"
        request = testbench.common.FakeRequest(
            args={"name": "object-name"},
            data=media,
            headers={},
            environ={},
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)
        new_acl = list(blob.metadata.acl)
        new_acl.append(
            storage_pb2.ObjectAccessControl(
                entity="allAuthenticatedUsers", role="READER"
            )
        )
        request = storage_pb2.UpdateObjectRequest(
            object=storage_pb2.Object(
                bucket="projects/_/buckets/bucket-name",
                name="object-name",
                acl=list(new_acl),
            ),
            update_mask=field_mask_pb2.FieldMask(paths=["acl"]),
        )
        context = unittest.mock.Mock()
        response = self.grpc.UpdateObject(request, context)
        context.abort.assert_not_called()
        self.assertEqual(new_acl, response.acl)

    def test_object_write(self):
        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={
                    "name": "object-name",
                    "bucket": "projects/_/buckets/bucket-name",
                },
            ),
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = QUANTUM
        content = media[QUANTUM : 2 * QUANTUM]
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = 2 * QUANTUM
        content = media[QUANTUM:]
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=QUANTUM,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )

        write = self.grpc.WriteObject([r1, r2, r3], context=self.mock_context())
        self.assertIsNotNone(write)
        self.assertIsNotNone(write.resource)
        blob = write.resource
        self.assertEqual(blob.name, "object-name", msg=write)
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_object_write_invalid_request(self):
        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        write = self.grpc.WriteObject([], context)
        context.abort.assert_called_once()
        self.assertIsNone(write)

    def test_object_write_incomplete(self):
        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={
                    "name": "object-name",
                    "bucket": "projects/_/buckets/bucket-name",
                },
            ),
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        context = self.mock_context()
        context.abort = unittest.mock.MagicMock()
        write = self.grpc.WriteObject([r1], context)
        context.abort.assert_called_once()
        self.assertIsNone(write)

    def test_object_write_conditional(self):
        media = TestGrpc._create_block(1024).encode("utf-8")
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={
                    "name": "object-name",
                    "bucket": "projects/_/buckets/bucket-name",
                },
                if_generation_match=0,
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=media, crc32c=crc32c.crc32c(media)
            ),
            finish_write=True,
        )

        write = self.grpc.WriteObject([r1], context=self.mock_context())
        self.assertIsNotNone(write)
        self.assertIsNotNone(write.resource)
        blob = write.resource
        self.assertEqual(blob.name, "object-name", msg=write)
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_object_write_conditional_overwrite(self):
        media = TestGrpc._create_block(1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)

        media = TestGrpc._create_block(1024).encode("utf-8")
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={
                    "name": "object-name",
                    "bucket": "projects/_/buckets/bucket-name",
                },
                if_generation_match=0,
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=media, crc32c=crc32c.crc32c(media)
            ),
            finish_write=True,
        )
        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        context.invocation_metadata = unittest.mock.MagicMock(return_value=dict())
        self.grpc.WriteObject([r1], context=context)
        context.abort.assert_called_once()

    def test_rewrite_object(self):
        # We need a large enough payload to make sure the first rewrite does
        # not complete.  The minimum is 1 MiB
        media = b"The quick brown fox jumps over the lazy dog\n" * 1024 * 1024
        request = testbench.common.FakeRequest(
            args={"name": "test-source-object"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)

        done = False
        token = ""
        while not done:
            context = unittest.mock.Mock()
            context.invocation_metadata = unittest.mock.MagicMock(return_value=dict())
            response = self.grpc.RewriteObject(
                storage_pb2.RewriteObjectRequest(
                    destination_bucket="projects/_/buckets/bucket-name",
                    destination_name="object-name",
                    source_bucket="projects/_/buckets/bucket-name",
                    source_object="test-source-object",
                    rewrite_token=token,
                    max_bytes_rewritten_per_call=1024,
                ),
                context,
            )
            context.abort.assert_not_called()
            done = response.done
            token = response.rewrite_token
        self.assertTrue(done)
        self.assertEqual(token, "")
        self.assertEqual(response.resource.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(response.resource.name, "object-name")
        self.assertEqual(response.resource.size, len(media))

        # Verify the newly created object has the right contents
        context = unittest.mock.Mock()
        get = self.grpc.GetObject(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            context,
        )
        self.assertEqual(get.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(get.name, "object-name")
        self.assertNotEqual(0, get.generation)
        self.assertEqual(get.size, len(media))

    def test_rewrite_object_with_destination(self):
        # A small payload works for this test
        media = b"The quick brown fox jumps over the lazy dog\n"
        request = testbench.common.FakeRequest(
            args={"name": "test-source-object"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)

        context = unittest.mock.Mock()
        context.invocation_metadata = unittest.mock.MagicMock(return_value=dict())
        response = self.grpc.RewriteObject(
            storage_pb2.RewriteObjectRequest(
                destination_bucket="projects/_/buckets/bucket-name",
                destination_name="object-name",
                source_bucket="projects/_/buckets/bucket-name",
                source_object="test-source-object",
                rewrite_token="",
                max_bytes_rewritten_per_call=1024,
                destination=storage_pb2.Object(cache_control="test-only-invalid"),
            ),
            context,
        )
        context.abort.assert_not_called()
        self.assertTrue(response.done)
        self.assertEqual(response.resource.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(response.resource.name, "object-name")
        self.assertEqual(response.resource.cache_control, "test-only-invalid")
        self.assertEqual(response.resource.size, len(media))

        # Verify the newly created object has the right contents
        context = unittest.mock.Mock()
        get = self.grpc.GetObject(
            storage_pb2.GetObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            context,
        )
        self.assertEqual(get.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(get.name, "object-name")
        self.assertNotEqual(0, get.generation)
        self.assertEqual(get.size, len(media))

    def test_resumable_write(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context=self.mock_context(),
        )
        self.assertIsNotNone(start.upload_id)

        def streamer():
            media = TestGrpc._create_block(517 * 1024).encode("utf-8")
            step = 256 * 1024
            end = min(step, len(media))
            content = media[0:end]
            # The first message is special, it should have a an upload id.
            yield storage_pb2.WriteObjectRequest(
                upload_id=start.upload_id,
                write_offset=0,
                checksummed_data=storage_pb2.ChecksummedData(
                    content=content, crc32c=crc32c.crc32c(content)
                ),
                finish_write=(end == len(media)),
            )

            for offset in range(step, len(media), step):
                end = min(offset + step, len(media))
                content = media[offset:end]
                yield storage_pb2.WriteObjectRequest(
                    write_offset=offset,
                    checksummed_data=storage_pb2.ChecksummedData(
                        content=content, crc32c=crc32c.crc32c(content)
                    ),
                    finish_write=(end == len(media)),
                )

        write = self.grpc.WriteObject(streamer(), "fake-context")
        self.assertIsNotNone(write)
        self.assertIsNotNone(write.resource)
        blob = write.resource
        self.assertEqual(blob.name, "object-name", msg=write)
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_resumable_resumes(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context=unittest.mock.MagicMock(),
        )
        self.assertIsNotNone(start.upload_id)

        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )
        write = self.grpc.WriteObject([r1], "fake-context")
        self.assertIsNotNone(write)
        self.assertEqual(write.persisted_size, QUANTUM)

        status = self.grpc.QueryWriteStatus(
            storage_pb2.QueryWriteStatusRequest(upload_id=start.upload_id),
            "fake-context",
        )
        self.assertEqual(status.persisted_size, QUANTUM)

        offset = QUANTUM
        content = media[QUANTUM : 2 * QUANTUM]
        r2 = storage_pb2.WriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = 2 * QUANTUM
        content = media[2 * QUANTUM :]
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=QUANTUM,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )
        write = self.grpc.WriteObject([r2, r3], "fake-context")
        self.assertIsNotNone(write)
        blob = write.resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_resumable_query_completed(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context=unittest.mock.MagicMock(),
        )
        self.assertIsNotNone(start.upload_id)

        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = QUANTUM
        content = media[QUANTUM:]
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )
        write = self.grpc.WriteObject([r1, r2], "fake-context")
        self.assertIsNotNone(write)
        blob = write.resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

        # If the application crashes before checkpointing the upload status, it
        # may query the upload status on restart.  The testbench should return
        # the full object metadata.

        status = self.grpc.QueryWriteStatus(
            storage_pb2.QueryWriteStatusRequest(upload_id=start.upload_id),
            "fake-context",
        )
        self.assertTrue(status.HasField("resource"))
        blob = status.resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(blob.size, len(media))

    def test_list_objects(self):
        names = ["a/test-0", "a/test-1", "a/b/test-0", "a/b/test-1", "c/test-0"]
        media = b"The quick brown fox jumps over the lazy dog"
        for name in names:
            request = testbench.common.FakeRequest(
                args={"name": name}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object("bucket-name", blob, None)
        context = unittest.mock.Mock()
        response = self.grpc.ListObjects(
            storage_pb2.ListObjectsRequest(
                parent="projects/_/buckets/bucket-name",
                prefix="a/",
                delimiter="/",
            ),
            context,
        )
        self.assertEqual(response.prefixes, ["a/b/"])
        response_names = [o.name for o in response.objects]
        self.assertEqual(response_names, ["a/test-0", "a/test-1"])

    def test_list_objects_offsets(self):
        names = [
            "a/a/test-0",
            "a/b/test-1",
            "a/b/x/test-5",
            "a/b/x/test-6",
            "a/c/test-2",
            "a/d/test-3",
            "a/e/test-4",
        ]
        media = b"The quick brown fox jumps over the lazy dog"
        for name in names:
            request = testbench.common.FakeRequest(
                args={"name": name}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object("bucket-name", blob, None)
        context = unittest.mock.Mock()
        response = self.grpc.ListObjects(
            storage_pb2.ListObjectsRequest(
                parent="projects/_/buckets/bucket-name",
                prefix="a/",
                lexicographic_start="a/b/",
                lexicographic_end="a/e/",
            ),
            context,
        )
        self.assertEqual(response.prefixes, [])
        response_names = [o.name for o in response.objects]
        self.assertEqual(
            response_names,
            [
                "a/b/test-1",
                "a/b/x/test-5",
                "a/b/x/test-6",
                "a/c/test-2",
                "a/d/test-3",
            ],
        )

    def test_list_objects_match_glob(self):
        names = [
            "a/a/1.txt",
            "a/b/1.py",
            "a/b/x/1.txt",
            "a/b/x/1.py",
            "a/c/1.txt",
            "a/d/1.py",
            "a/e/1.cc",
            "b/e/2.txt",
            "b/e/2.py",
        ]
        media = b"The quick brown fox jumps over the lazy dog"
        for name in names:
            request = testbench.common.FakeRequest(
                args={"name": name}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object("bucket-name", blob, None)
        context = unittest.mock.Mock()
        response = self.grpc.ListObjects(
            storage_pb2.ListObjectsRequest(
                parent="projects/_/buckets/bucket-name",
                prefix="a/",
                match_glob="**/*.py",
            ),
            context,
        )
        self.assertEqual(response.prefixes, [])
        response_names = [o.name for o in response.objects]
        self.assertEqual(
            response_names,
            [
                "a/b/1.py",
                "a/b/x/1.py",
                "a/d/1.py",
            ],
        )

    def test_list_objects_trailing_delimiters(self):
        names = [
            "a/a/",
            "a/a/test-0",
            "a/b/",
            "a/b/test-1",
            "a/c/test-2",
            "a/test-3",
        ]
        media = b"The quick brown fox jumps over the lazy dog"
        for name in names:
            request = testbench.common.FakeRequest(
                args={"name": name}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object("bucket-name", blob, None)
        cases = [
            {"include_trailing_delimiter": False, "expected": ["a/test-3"]},
            {
                "include_trailing_delimiter": True,
                "expected": ["a/a/", "a/b/", "a/test-3"],
            },
        ]
        for case in cases:
            context = unittest.mock.Mock()
            response = self.grpc.ListObjects(
                storage_pb2.ListObjectsRequest(
                    parent="projects/_/buckets/bucket-name",
                    prefix="a/",
                    delimiter="/",
                    include_trailing_delimiter=case["include_trailing_delimiter"],
                ),
                context,
            )
            self.assertEqual(response.prefixes, ["a/a/", "a/b/", "a/c/"])
            response_names = [o.name for o in response.objects]
            self.assertEqual(response_names, case["expected"], msg=case)

    def test_get_service_account(self):
        context = unittest.mock.Mock()
        response = self.grpc.GetServiceAccount(
            storage_pb2.GetServiceAccountRequest(project="projects/test-project"),
            context,
        )
        self.assertIn("@", response.email_address)

    def test_get_service_account_failure(self):
        context = unittest.mock.Mock()
        _ = self.grpc.GetServiceAccount(
            storage_pb2.GetServiceAccountRequest(project="invalid-format"),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_create_hmac_key(self):
        sa_email = "test-sa@test-project-id.iam.gserviceaccount.com"
        context = unittest.mock.Mock()
        response = self.grpc.CreateHmacKey(
            storage_pb2.CreateHmacKeyRequest(
                project="projects/test-project-id",
                service_account_email=sa_email,
            ),
            context,
        )
        self.assertNotEqual(response.secret_key_bytes, "")
        self.assertNotEqual(response.metadata.id, "")
        self.assertNotEqual(response.metadata.access_id, "")
        self.assertEqual(response.metadata.service_account_email, sa_email)
        self.assertNotEqual(response.metadata.etag, "")

        context = unittest.mock.Mock()
        _ = self.grpc.CreateHmacKey(
            storage_pb2.CreateHmacKeyRequest(
                project="invalid-project-name-format",
                service_account_email=sa_email,
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

        # Missing service account emails should fail
        context = unittest.mock.Mock()
        _ = self.grpc.CreateHmacKey(
            storage_pb2.CreateHmacKeyRequest(
                project="projects/test-project-id",
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_delete_hmac_key(self):
        sa_email = "test-sa@test-project-id.iam.gserviceaccount.com"
        context = unittest.mock.Mock()
        create = self.grpc.CreateHmacKey(
            storage_pb2.CreateHmacKeyRequest(
                project="projects/test-project-id",
                service_account_email=sa_email,
            ),
            context,
        )

        metadata = storage_pb2.HmacKeyMetadata()
        metadata.CopyFrom(create.metadata)
        metadata.state = "INACTIVE"

        context = unittest.mock.Mock()
        response = self.grpc.UpdateHmacKey(
            storage_pb2.UpdateHmacKeyRequest(
                hmac_key=metadata, update_mask=field_mask_pb2.FieldMask(paths=["state"])
            ),
            context,
        )
        self.assertEqual(response.state, "INACTIVE")

        context = unittest.mock.Mock()
        _ = self.grpc.DeleteHmacKey(
            storage_pb2.DeleteHmacKeyRequest(
                access_id=metadata.access_id, project=metadata.project
            ),
            context,
        )
        context.abort.assert_not_called()

        # The code depends on `context.abort()` raising an exception.
        context.abort = unittest.mock.MagicMock()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            _ = self.grpc.GetHmacKey(
                storage_pb2.GetHmacKeyRequest(
                    access_id=metadata.access_id, project="projects/test-project-id"
                ),
                context,
            )
        context.abort.assert_called_once_with(
            grpc.StatusCode.NOT_FOUND, unittest.mock.ANY
        )

        # Missing or malformed project id is an error
        context = unittest.mock.Mock()
        _ = self.grpc.DeleteHmacKey(
            storage_pb2.DeleteHmacKeyRequest(access_id=metadata.access_id),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_get_hmac_key(self):
        sa_email = "test-sa@test-project-id.iam.gserviceaccount.com"
        context = unittest.mock.Mock()
        create = self.grpc.CreateHmacKey(
            storage_pb2.CreateHmacKeyRequest(
                project="projects/test-project-id",
                service_account_email=sa_email,
            ),
            context,
        )

        context = unittest.mock.Mock()
        response = self.grpc.GetHmacKey(
            storage_pb2.GetHmacKeyRequest(
                access_id=create.metadata.access_id, project="projects/test-project-id"
            ),
            context,
        )
        self.assertEqual(response, create.metadata)

        # Missing or malformed project id is an error
        context = unittest.mock.Mock()
        _ = self.grpc.GetHmacKey(
            storage_pb2.GetHmacKeyRequest(access_id=create.metadata.access_id),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_list_hmac_keys(self):
        # Create several keys for two different projects.
        expected = []
        sa_emails = [
            "test-sa-1@test-project-id.iam.gserviceaccount.com",
            "test-sa-2@test-project-id.iam.gserviceaccount.com",
        ]
        for sa in sa_emails:
            for _ in [1, 2]:
                context = unittest.mock.Mock()
                create = self.grpc.CreateHmacKey(
                    storage_pb2.CreateHmacKeyRequest(
                        project="projects/test-project-id",
                        service_account_email=sa,
                    ),
                    context,
                )
                expected.append(create.metadata)

        # First test without any filtering
        context = unittest.mock.Mock()
        response = self.grpc.ListHmacKeys(
            storage_pb2.ListHmacKeysRequest(project="projects/test-project-id"),
            context,
        )
        expected_access_ids = {k.access_id for k in expected}
        self.assertEqual({k.access_id for k in response.hmac_keys}, expected_access_ids)

        # Then only for one of the sa emails
        context = unittest.mock.Mock()
        sa_filter = sa_emails[0]
        response = self.grpc.ListHmacKeys(
            storage_pb2.ListHmacKeysRequest(
                project="projects/test-project-id", service_account_email=sa_filter
            ),
            context,
        )
        expected_access_ids = {
            k.access_id for k in expected if k.service_account_email == sa_filter
        }
        self.assertEqual({k.access_id for k in response.hmac_keys}, expected_access_ids)

        # Include deleted accounts (there are none, but should work)
        context = unittest.mock.Mock()
        sa_filter = sa_emails[0]
        response = self.grpc.ListHmacKeys(
            storage_pb2.ListHmacKeysRequest(
                project="projects/test-project-id",
                service_account_email=sa_filter,
                show_deleted_keys=True,
            ),
            context,
        )
        expected_access_ids = {
            k.access_id for k in expected if k.service_account_email == sa_filter
        }
        self.assertEqual({k.access_id for k in response.hmac_keys}, expected_access_ids)

        # Missing or malformed project id is an error
        context = unittest.mock.Mock()
        _ = self.grpc.ListHmacKeys(storage_pb2.ListHmacKeysRequest(), context)
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_update_hmac_key(self):
        sa_email = "test-sa@test-project-id.iam.gserviceaccount.com"
        context = unittest.mock.Mock()
        create = self.grpc.CreateHmacKey(
            storage_pb2.CreateHmacKeyRequest(
                project="projects/test-project-id",
                service_account_email=sa_email,
            ),
            context,
        )

        metadata = storage_pb2.HmacKeyMetadata()
        metadata.CopyFrom(create.metadata)
        metadata.state = "INACTIVE"

        context = unittest.mock.Mock()
        response = self.grpc.UpdateHmacKey(
            storage_pb2.UpdateHmacKeyRequest(
                hmac_key=metadata, update_mask=field_mask_pb2.FieldMask(paths=["state"])
            ),
            context,
        )
        self.assertEqual(response.id, metadata.id)
        self.assertEqual(response.access_id, metadata.access_id)
        self.assertEqual(response.project, metadata.project)
        self.assertEqual(response.service_account_email, metadata.service_account_email)
        self.assertEqual(response.state, metadata.state)
        self.assertEqual(response.create_time, metadata.create_time)

        # Verify a missing, empty, or invalid update mask returns an error
        for mask in [[], ["not-state"], ["state", "and-more"]]:
            context = unittest.mock.Mock()
            _ = self.grpc.UpdateHmacKey(
                storage_pb2.UpdateHmacKeyRequest(
                    hmac_key=metadata, update_mask=field_mask_pb2.FieldMask(paths=mask)
                ),
                context,
            )
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )

        # An empty metadata attribute is also an error
        context = unittest.mock.Mock()
        _ = self.grpc.UpdateHmacKey(
            storage_pb2.UpdateHmacKeyRequest(
                hmac_key=storage_pb2.HmacKeyMetadata(),
                update_mask=field_mask_pb2.FieldMask(paths=["state"]),
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_update_hmac_key_bad_etag(self):
        sa_email = "test-sa@test-project-id.iam.gserviceaccount.com"
        context = unittest.mock.Mock()
        create = self.grpc.CreateHmacKey(
            storage_pb2.CreateHmacKeyRequest(
                project="projects/test-project-id",
                service_account_email=sa_email,
            ),
            context,
        )

        metadata = storage_pb2.HmacKeyMetadata()
        metadata.CopyFrom(create.metadata)
        metadata.state = "INACTIVE"
        metadata.etag = "test-only-invalid"

        context = unittest.mock.Mock()
        response = self.grpc.UpdateHmacKey(
            storage_pb2.UpdateHmacKeyRequest(
                hmac_key=metadata, update_mask=field_mask_pb2.FieldMask(paths=["state"])
            ),
            context,
        )
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_run(self):
        port, server = testbench.grpc_server.run(0, self.db)
        self.assertNotEqual(port, 0)
        self.assertIsNotNone(server)

        stub = storage_pb2_grpc.StorageStub(
            grpc.insecure_channel("localhost:%d" % port)
        )
        start = stub.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
        )
        self.assertIsNotNone(start.upload_id)
        self.assertNotEqual(start.upload_id, "")
        server.stop(grace=0)

    def test_echo_metadata(self):
        port, server = testbench.grpc_server.run(0, self.db, echo_metadata=True)
        self.assertNotEqual(port, 0)
        self.assertIsNotNone(server)

        stub = storage_pb2_grpc.StorageStub(
            grpc.insecure_channel("localhost:%d" % port)
        )
        request = storage_pb2.GetBucketRequest(name="projects/_/buckets/bucket-name")
        response, call = stub.GetBucket.with_call(request, metadata=(("hdr1", "foo"),))
        self.assertIn(("x-req-hdr1", "foo"), call.initial_metadata())
        server.stop(grace=0)

    def test_bidi_write_object(self):
        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.BidiWriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={
                    "name": "object-name",
                    "bucket": "projects/_/buckets/bucket-name",
                },
            ),
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            flush=True,
            state_lookup=True,
            finish_write=False,
        )

        offset = QUANTUM
        content = media[QUANTUM : 2 * QUANTUM]
        r2 = storage_pb2.BidiWriteObjectRequest(
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            flush=True,
            state_lookup=True,
            finish_write=False,
        )

        offset = 2 * QUANTUM
        content = media[QUANTUM:]
        r3 = storage_pb2.BidiWriteObjectRequest(
            write_offset=QUANTUM,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )
        streamer = self.grpc.BidiWriteObject([r1, r2, r3], context=self.mock_context())
        responses = list(streamer)
        # We expect a total of 3 responses with state_lookup set to True.
        self.assertEqual(len(responses), 3)
        self.assertIsNotNone(responses[0].persisted_size)
        self.assertIsNotNone(responses[1].persisted_size)
        self.assertIsNotNone(responses[2].resource)
        blob = responses[2].resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_bidi_write_object_resumable(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context=unittest.mock.MagicMock(),
        )
        self.assertIsNotNone(start.upload_id)

        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")
        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.BidiWriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            flush=True,
            finish_write=False,
        )
        offset = QUANTUM
        content = media[QUANTUM : 2 * QUANTUM]
        r2 = storage_pb2.BidiWriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            flush=True,
            state_lookup=True,
            finish_write=False,
        )
        streamer = self.grpc.BidiWriteObject([r1, r2], "fake-context")
        responses = list(streamer)
        # We only expect 1 response with r2 state_lookup set to True.
        self.assertEqual(len(responses), 1)
        self.assertIsNotNone(responses[0])
        self.assertEqual(responses[0].persisted_size, 2 * QUANTUM)

        status = self.grpc.QueryWriteStatus(
            storage_pb2.QueryWriteStatusRequest(upload_id=start.upload_id),
            "fake-context",
        )
        self.assertEqual(status.persisted_size, 2 * QUANTUM)

        offset = 2 * QUANTUM
        content = media[2 * QUANTUM :]
        r3 = storage_pb2.BidiWriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=QUANTUM,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )
        streamer = self.grpc.BidiWriteObject([r3], "fake-context")
        responses = list(streamer)
        self.assertEqual(len(responses), 1)
        blob = responses[0].resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_bidi_read_object(self):
        # Create object in database to read.
        media = TestGrpc._create_block(5 * 1024 * 1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)

        # Test n ranges in 1 stream, where n=2.
        offset_1 = 0
        limit_1 = 2 * 1024 * 1024
        read_id_1 = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        offset_2 = 3 * 1024 * 1024
        limit_2 = 2 * 1024 * 1024
        read_id_2 = read_id_1 + 1

        r1 = storage_pb2.BidiReadObjectRequest(
            read_object_spec=storage_pb2.BidiReadObjectSpec(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
            ),
            read_ranges=[
                storage_pb2.ReadRange(
                    read_offset=offset_1,
                    read_limit=limit_1,
                    read_id=read_id_1,
                ),
                storage_pb2.ReadRange(
                    read_offset=offset_2,
                    read_limit=limit_2,
                    read_id=read_id_2,
                ),
            ],
        )

        streamer = self.grpc.BidiReadObject([r1], context=self.mock_context())
        returned_by_readid = {
            read_id_1: offset_1,
            read_id_2: offset_2,
        }
        for resp in streamer:
            for range in resp.object_data_ranges:
                read_id = range.read_range.read_id
                offset = range.read_range.read_offset
                self.assertEqual(returned_by_readid[read_id], offset)

                data = range.checksummed_data
                self.assertEqual(crc32c.crc32c(data.content), data.crc32c)
                returned_by_readid[read_id] += len(data.content)

        self.assertEqual(returned_by_readid[read_id_1], offset_1 + limit_1)
        self.assertEqual(returned_by_readid[read_id_2], offset_2 + limit_2)

    def test_bidi_read_object_not_found(self):
        # Test BidiReadObject with non-existent object.
        nonexistent_object_name = "object-name2"
        r1 = storage_pb2.BidiReadObjectRequest(
            read_object_spec=storage_pb2.BidiReadObjectSpec(
                bucket="projects/_/buckets/bucket-name",
                object=nonexistent_object_name,
            ),
            read_ranges=[],
        )
        # The code depends on `context.abort()` raising an exception.
        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            streamer = self.grpc.BidiReadObject([r1], context=context)
            list(streamer)
        context.abort.assert_called_once_with(
            grpc.StatusCode.NOT_FOUND, unittest.mock.ANY
        )

        # Test BidiReadObject with invalid object generation.
        # Create object in database to read.
        media = TestGrpc._create_block(1024 * 1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)
        obj = self.db.get_object("bucket-name", "object-name", None)
        invalid_generation = obj.metadata.generation + 1
        r2 = storage_pb2.BidiReadObjectRequest(
            read_object_spec=storage_pb2.BidiReadObjectSpec(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                generation=invalid_generation,
            ),
            read_ranges=[],
        )
        # The code depends on `context.abort()` raising an exception.
        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            streamer = self.grpc.BidiReadObject([r2], context=context)
            list(streamer)
        context.abort.assert_called_once_with(
            grpc.StatusCode.NOT_FOUND, unittest.mock.ANY
        )

    def test_bidi_read_object_generation_precondition_failed(self):
        # Create object in database to read.
        media = TestGrpc._create_block(1024 * 1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)

        # Test BidiReadObject with invalid object generation match precondition.
        invalid_generation_match = 0
        offset_1 = 0
        limit_1 = 1024
        read_id_1 = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        r1 = storage_pb2.BidiReadObjectRequest(
            read_object_spec=storage_pb2.BidiReadObjectSpec(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
                if_generation_match=invalid_generation_match,
            ),
            read_ranges=[
                storage_pb2.ReadRange(
                    read_offset=offset_1,
                    read_limit=limit_1,
                    read_id=read_id_1,
                ),
            ],
        )
        # The code depends on `context.abort()` raising an exception.
        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            streamer = self.grpc.BidiReadObject([r1], context=context)
            list(streamer)
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_bidi_read_object_interleaves_responses(self):
        # This lets the test pass in a reasonale amount of time - otherwise the
        # test harness prints a _lot_ to stdout.
        OLD_CHUNK = storage_pb2.ServiceConstants.Values.MAX_READ_CHUNK_BYTES
        try:
            CHUNK = 100
            storage_pb2.ServiceConstants.Values.MAX_READ_CHUNK_BYTES = CHUNK
            # 100 ranges of 2 chunks each. Empirically, that makes this test
            # flake fewer than 1 in 10,000 runs.
            media = TestGrpc._create_block(100 * 2 * CHUNK).encode("utf-8")
            request = testbench.common.FakeRequest(
                args={"name": f"object-name"}, data=media, headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.db.insert_object("bucket-name", blob, None)

            def make_2_chunk_range(i):
                return storage_pb2.ReadRange(
                    read_offset=2 * CHUNK * i,
                    read_limit=2 * CHUNK,
                    read_id=i,
                )

            first_read_ranges = [make_2_chunk_range(i) for i in range(50)]
            second_read_ranges = [make_2_chunk_range(i) for i in range(50, 100)]

            r1 = storage_pb2.BidiReadObjectRequest(
                read_object_spec=storage_pb2.BidiReadObjectSpec(
                    bucket="projects/_/buckets/bucket-name",
                    object="object-name",
                ),
                read_ranges=first_read_ranges,
            )
            r2 = storage_pb2.BidiReadObjectRequest(
                read_ranges=second_read_ranges,
            )

            def response_to_ranges(resp):
                return [
                    (range.read_range.read_id, range.read_range.read_offset)
                    for range in resp.object_data_ranges
                ]

            streamer = self.grpc.BidiReadObject([r1, r2], context=self.mock_context())
            response_ranges = [response_to_ranges(resp) for resp in list(streamer)]
            self.assertNotEqual(sorted(response_ranges), response_ranges)
        finally:
            storage_pb2.ServiceConstants.Values.MAX_READ_CHUNK_BYTES = OLD_CHUNK

    def test_bidi_read_no_messages_sent(self):
        streamer = self.grpc.BidiReadObject([], context=self.mock_context())
        self.assertEqual(len(list(streamer)), 0)  # No responses, does not raise

    def test_bidi_read_out_of_range_error(self):
        # Create object in database to read.
        media = TestGrpc._create_block(1024 * 1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)

        # Test out-of-range offset.
        offset_1 = 8 * 1024 * 1024
        limit_1 = 1024
        read_id_1 = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        r1 = storage_pb2.BidiReadObjectRequest(
            read_object_spec=storage_pb2.BidiReadObjectSpec(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
            ),
            read_ranges=[
                storage_pb2.ReadRange(
                    read_offset=offset_1,
                    read_limit=limit_1,
                    read_id=read_id_1,
                ),
            ],
        )
        # Test out-of-range with negative read limit.
        limit_2 = -2048
        offset_2 = 10
        read_id_2 = read_id_1 + 1
        r2 = storage_pb2.BidiReadObjectRequest(
            read_object_spec=storage_pb2.BidiReadObjectSpec(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
            ),
            read_ranges=[
                storage_pb2.ReadRange(
                    read_offset=offset_2,
                    read_limit=limit_2,
                    read_id=read_id_2,
                ),
            ],
        )

        for request in [r1, r2]:
            context = unittest.mock.Mock()
            context.abort_with_status = unittest.mock.MagicMock()
            context.abort_with_status.side_effect = grpc.RpcError()
            with self.assertRaises(grpc.RpcError):
                streamer = self.grpc.BidiReadObject([request], context=context)
                list(streamer)

            context.abort_with_status.assert_called_once()
            abort_status = context.abort_with_status.call_args[0][0]
            grpc_status_details_bin = abort_status.trailing_metadata[0][1]
            self.assertIsInstance(abort_status, grpc_status.rpc_status._Status)
            self.assertIn(grpc.StatusCode.OUT_OF_RANGE, abort_status)
            self.assertIn(b"BidiReadObjectError", grpc_status_details_bin)

    def test_bidi_read_one_out_of_range_one_in_range_error(self):
        # Create object in database to read.
        media = TestGrpc._create_block(1024 * 1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object("bucket-name", blob, None)

        # Test out-of-range offset.
        offset_1 = 8 * 1024 * 1024
        limit_1 = 1024
        read_id_1 = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        r1 = storage_pb2.BidiReadObjectRequest(
            read_object_spec=storage_pb2.BidiReadObjectSpec(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
            ),
            read_ranges=[
                storage_pb2.ReadRange(
                    read_offset=offset_1,
                    read_limit=limit_1,
                    read_id=read_id_1,
                ),
            ],
        )
        # Test in-range offset.
        offset_2 = 0
        limit_2 = 10
        read_id_2 = read_id_1 + 1
        r2 = storage_pb2.BidiReadObjectRequest(
            read_object_spec=storage_pb2.BidiReadObjectSpec(
                bucket="projects/_/buckets/bucket-name",
                object="object-name",
            ),
            read_ranges=[
                storage_pb2.ReadRange(
                    read_offset=offset_2,
                    read_limit=limit_2,
                    read_id=read_id_2,
                ),
            ],
        )

        context = unittest.mock.Mock()
        context.abort_with_status = unittest.mock.MagicMock()
        context.abort_with_status.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            streamer = self.grpc.BidiReadObject([r1, r2], context=context)
            list(streamer)

        context.abort_with_status.assert_called_once()
        abort_status = context.abort_with_status.call_args[0][0]
        grpc_status_details_bin = abort_status.trailing_metadata[0][1]
        self.assertIsInstance(abort_status, grpc_status.rpc_status._Status)
        self.assertIn(grpc.StatusCode.OUT_OF_RANGE, abort_status)
        self.assertIn(b"BidiReadObjectError", grpc_status_details_bin)


if __name__ == "__main__":
    unittest.main()
