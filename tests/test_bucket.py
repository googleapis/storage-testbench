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

"""Tests for the Bucket class (see gcs/bucket.py)."""

import json
import unittest

import google.protobuf.duration_pb2 as duration_pb2
import google.protobuf.timestamp_pb2 as timestamp_pb2
from google.protobuf import json_format

import gcs
import testbench


class TestBucket(unittest.TestCase):
    def _validate_bucket_acl(self, acl, bucket_name):
        for entry in acl:
            self.assertEqual(entry.pop("kind", None), "storage#bucketAccessControl")
            self.assertEqual(entry.pop("bucket", None), bucket_name)
            self.assertIsNotNone(entry.pop("entity", None))
            self.assertIsNotNone(entry.pop("role", None))
            # Verify the remaining keys are a subset of the expected keys
            self.assertLessEqual(
                set(entry.keys()),
                {
                    "id",
                    "selfLink",
                    "email",
                    "entityId",
                    "domain",
                    "projectTeam",
                    "etag",
                },
            )

    def _validate_default_object_acl(self, acl, bucket_name):
        for entry in acl:
            self.assertEqual(entry.pop("kind", None), "storage#objectAccessControl")
            self.assertEqual(entry.pop("bucket", None), bucket_name)
            self.assertIsNotNone(entry.pop("entity", None))
            self.assertIsNotNone(entry.pop("role", None))
            # Verify the remaining keys are a subset of the expected keys
            self.assertLessEqual(
                set(entry.keys()),
                {
                    "id",
                    "selfLink",
                    "email",
                    "entityId",
                    "domain",
                    "projectTeam",
                    "etag",
                },
            )

    def test_init_simple(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(bucket.metadata.name, "projects/_/buckets/bucket")
        self.assertEqual(bucket.metadata.bucket_id, "bucket")
        self.assertLess(0, bucket.metadata.metageneration)
        self.assertNotEqual(bucket.metadata.etag, "")

    def test_init_validates_names(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "short.names.for.domain.buckets.example.com"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(
            bucket.metadata.name,
            "projects/_/buckets/short.names.for.domain.buckets.example.com",
        )
        invalid_names = [
            "goog-is-not-a-valid-prefix",
            "hiding-google-is-not-valid",
            "hiding-g00gl3-is-not-valid",
            "name-too-long-" + ("a" * 63),
            ("a" * 64) + ".part-too-long.com",
            ("a" * 222) + ".domain-name-too-long.com",
        ]
        for name in invalid_names:
            request = testbench.common.FakeRequest(
                args={},
                data=json.dumps({"name": name}),
            )
            with self.assertRaises(testbench.error.RestException, msg=name) as rest:
                bucket, _ = gcs.bucket.Bucket.init(request, None)
            self.assertEqual(rest.exception.code, 400)

    def test_init_rest(self):
        metadata = {
            "name": "test-bucket-name",
            "metageneration": "1",
            "defaultEventBasedHold": True,
            "retentionPolicy": {
                "retentionPeriod": "90",
                "effectiveTime": "2021-09-01T02:03:04Z",
                "isLocked": True,
            },
            "acl": [{"entity": "allAuthenticatedUsers", "role": "READER"}],
            "defaultObjectAcl": [{"entity": "allAuthenticatedUsers", "role": "READER"}],
            "iamConfiguration": {
                "publicAccessPrevention": "enforced",
                "uniformBucketLevelAccess": {
                    "enabled": True,
                    "lockedTime": "2023-01-01T01:02:03Z",
                },
            },
            "encryption": {"defaultKmsKeyName": "test-only-value-"},
            "location": "us-central1",
            "locationType": "REGIONAL",
            "website": {"mainPageSuffix": "html", "notFoundPage": "404.html"},
            "logging": {
                "logBucket": "test-only-value",
                "logObjectPrefix": "test-prefix/",
            },
            "versioning": {"enabled": True},
            "cors": [{"method": ["POST"]}],
            "lifecycle": {
                "rule": [
                    {
                        "action": {"type": "delete"},
                        "condition": {
                            "age": 60,
                            "createdBefore": "2023-08-01",
                            "customTimeBefore": "2024-08-01",
                            "daysSinceCustomTime": 90,
                            "daysSinceNoncurrentTime": 30,
                            "noncurrentTimeBefore": "2021-10-01",
                            "isLive": True,
                            "matchesStorageClass": ["STANDARD"],
                            "numNewerVersions": 42,
                        },
                    }
                ]
            },
            "labels": {"label0": "value0"},
            "storageClass": "regional",
            "billing": {"requesterPays": True},
            "rpo": "DEFAULT",
        }
        request = testbench.common.FakeRequest(args={}, data=json.dumps(metadata))
        bucket, projection = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(projection, "full")
        # Verify the name is stored in the correct format for gRPC
        self.assertEqual(bucket.metadata.name, "projects/_/buckets/test-bucket-name")
        bucket_rest = bucket.rest()
        # Some fields must exist in the REST message
        for required in ["metageneration", "kind", "name"]:
            self.assertIsNotNone(bucket_rest.get(required, None), msg=required)
        # Verify the BucketAccessControl entries have the desired fields
        metadata.pop("acl")
        acl = bucket_rest.pop("acl", None)
        self.assertLessEqual({"allAuthenticatedUsers"}, {e["entity"] for e in acl})
        self.assertIsNotNone(acl)
        self._validate_bucket_acl(acl, "test-bucket-name")
        # Verify the BucketAccessControl entries have the desired fields
        metadata.pop("defaultObjectAcl")
        default_object_acl = bucket_rest.pop("defaultObjectAcl", None)
        self.assertIsNotNone(default_object_acl)
        self.assertLessEqual(
            set(["allAuthenticatedUsers"]),
            set([e["entity"] for e in default_object_acl]),
        )
        self._validate_default_object_acl(default_object_acl, "test-bucket-name")
        # Some fields are inserted by `Bucket.init()`, we want to verify they
        # exist and have the right value.
        expected_new_fields = {"kind": "storage#bucket", "id": "test-bucket-name"}
        actual_new_fields = {
            k: bucket_rest.pop(k, None) for k, _ in expected_new_fields.items()
        }
        self.assertDictEqual(expected_new_fields, actual_new_fields)
        # Some fields are inserted by `Bucket.init()`, we want to verify they are
        # present, but their value is not that interesting.
        for key in ["timeCreated", "updated", "owner", "projectNumber", "etag"]:
            self.assertIsNotNone(bucket_rest.pop(key, None), msg="key=%s" % key)
        self.maxDiff = None
        self.assertDictEqual(metadata, bucket_rest)

        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "acl": [
                        json_format.MessageToDict(acl)
                        for acl in testbench.acl.compute_predefined_bucket_acl(
                            "bucket", "authenticatedRead", None
                        )
                    ],
                }
            ),
        )
        bucket, projection = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(bucket.metadata.name, "projects/_/buckets/bucket")
        self.assertEqual(projection, "full")

        def acl_sort(x):
            return (x.entity, x.role)

        self.assertEqual(
            bucket.metadata.acl.sort(key=acl_sort),
            testbench.acl.compute_predefined_bucket_acl(
                "bucket", "authenticatedRead", None
            ).sort(key=acl_sort),
        )

    def test_init_rest_pap(self):
        for pap in ["unspecified", "inherited"]:
            metadata = {
                "name": "test-bucket-name",
                "iamConfiguration": {
                    # The `unspecified` and `inherited` values have interesting behavior
                    "publicAccessPrevention": pap,
                },
            }
            request = testbench.common.FakeRequest(args={}, data=json.dumps(metadata))
            bucket, projection = gcs.bucket.Bucket.init(request, None)
            self.assertEqual(projection, "noAcl")
            bucket_rest = bucket.rest()
            self.assertEqual("storage#bucket", bucket_rest.get("kind"))
            self.assertEqual("test-bucket-name", bucket_rest.get("name"))
            self.assertEqual(
                {"uniformBucketLevelAccess": {}, "publicAccessPrevention": "inherited"},
                bucket_rest.get("iamConfiguration"),
            )

    def test_patch_rest(self):
        # Updating requires a full metadata so we don't test it here.
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "labels": {"init": "true", "patch": "false"},
                    "website": {"not_found_page": "notfound.html"},
                }
            ),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(bucket.metadata.labels.get("init"), "true")
        self.assertEqual(bucket.metadata.labels.get("patch"), "false")
        self.assertIsNone(bucket.metadata.labels.get("method"))
        self.assertEqual(bucket.metadata.website.main_page_suffix, "")
        self.assertEqual(bucket.metadata.website.not_found_page, "notfound.html")
        previous_metageneration = bucket.metadata.metageneration

        request = testbench.common.FakeRequest(
            args={"bucket": "bucket"},
            data=json.dumps(
                {
                    "labels": {"init": None, "patch": "true", "method": "rest"},
                    "website": {"main_page_suffix": "bucket"},
                }
            ),
        )
        bucket.patch(request, None)
        # GRPC can not update a part of map field.
        self.assertIsNone(bucket.metadata.labels.get("init"))
        self.assertEqual(bucket.metadata.labels.get("patch"), "true")
        self.assertEqual(bucket.metadata.labels.get("method"), "rest")
        self.assertEqual(bucket.metadata.website.main_page_suffix, "bucket")
        # `update_mask` does not update `website.not_found_page`
        self.assertEqual(bucket.metadata.website.not_found_page, "notfound.html")
        self.assertNotEqual(previous_metageneration, bucket.metadata.metageneration)

        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "new_bucket",
                    "labels": {"method": "rest"},
                    "website": {"notFoundPage": "404.html"},
                    "storageClass": "COLDLINE",
                }
            ),
        )
        bucket.patch(request, None)
        # REST should only update modifiable field.
        self.assertEqual(bucket.metadata.name, "projects/_/buckets/bucket")
        # REST can update a part of map field.
        self.assertIsNone(bucket.metadata.labels.get("init"))
        self.assertEqual(bucket.metadata.labels.get("patch"), "true")
        self.assertEqual(bucket.metadata.labels.get("method"), "rest")
        self.assertEqual(bucket.metadata.website.main_page_suffix, "bucket")
        self.assertEqual(bucket.metadata.website.not_found_page, "404.html")

        # We want to make sure REST `UPDATE` does not throw any exception.
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"labels": {"method": "rest_update"}})
        )
        bucket.update(request, None)
        self.assertEqual(bucket.metadata.labels["method"], "rest_update")

    def test_patch_autoclass_rest(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "autoclass": {"enabled": True},
                }
            ),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(bucket.metadata.autoclass.enabled, True)
        self.assertEqual(
            bucket.metadata.autoclass.toggle_time, bucket.metadata.create_time
        )

        request = testbench.common.FakeRequest(
            args={"bucket": "bucket"},
            data=json.dumps(
                {
                    "autoclass": {"enabled": False},
                }
            ),
        )
        bucket.patch(request, None)
        self.assertEqual(bucket.metadata.autoclass.enabled, False)
        self.assertEqual(
            bucket.metadata.autoclass.toggle_time, bucket.metadata.update_time
        )

    def test_notification(self):
        metadata = {
            "name": "test-bucket-name",
            "location": "us-central1",
            "locationType": "REGIONAL",
            "storageClass": "regional",
        }
        request = testbench.common.FakeRequest(args={}, data=json.dumps(metadata))
        bucket, _ = gcs.bucket.Bucket.init(request, None)

        expected = []
        for topic in ["test-topic-1", "test-topic-2"]:
            notification_rest = json.dumps(
                {"topic": topic, "payload_format": "JSON_API_V1"}
            )
            notification = bucket.insert_notification(notification_rest, None)
            self.assertEqual(notification["topic"], topic)

            get_result = bucket.get_notification(notification["id"], None)
            self.assertEqual(notification, get_result)
            expected.append(notification)

        list_result = bucket.list_notifications(None)
        self.assertDictEqual(
            list_result, {"kind": "storage#notifications", "items": expected}
        )
        for n in expected:
            bucket.delete_notification(n["id"], None)

        with self.assertRaises(Exception) as rest:
            bucket.get_notification(expected[0]["id"], None)
        self.assertEqual(rest.exception.code, 404)

        with self.assertRaises(Exception) as rest:
            bucket.delete_notification(expected[0]["id"], None)
        self.assertEqual(rest.exception.code, 404)

    @staticmethod
    def _find_role(role, policy):
        for binding in policy.bindings:
            if binding.role == role:
                return binding
        return None

    def test_iam_policy_rest(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = testbench.common.FakeRequest(args={}, data=json.dumps({}))
        policy = bucket.get_iam_policy(request, None)
        actual_roles = {binding.role for binding in policy.bindings}
        self.assertEqual(
            actual_roles,
            {
                "roles/storage.legacyBucketReader",
                "roles/storage.legacyBucketWriter",
                "roles/storage.legacyBucketOwner",
            },
        )
        role = policy.bindings[0].role
        policy.bindings[0].members.append("allAuthenticatedUsers")
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps(json_format.MessageToDict(policy))
        )
        # There is no guarantee the modified role will be at position 0 again
        new_policy = bucket.set_iam_policy(request, None)
        role_binding = self._find_role(role, new_policy)
        self.assertIsNotNone(role_binding)
        self.assertIn("allAuthenticatedUsers", role_binding.members)

    def test_acl_rest(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket-name"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "bucket": "bucket-name",
                    "role": "WRITER",
                    "entity": "test-entity@example.com",
                }
            ),
        )
        acl = bucket.insert_acl(request, None)
        self.assertEqual(acl.role, "WRITER")
        self.assertEqual(acl.entity, "test-entity@example.com")
        acl = bucket.update_acl(request, "test-entity@example.com", None)
        self.assertEqual(acl.role, "WRITER")
        self.assertEqual(acl.entity, "test-entity@example.com")
        acl = bucket.patch_acl(request, "test-entity@example.com", None)
        self.assertEqual(acl.role, "WRITER")
        self.assertEqual(acl.entity, "test-entity@example.com")

    def test_default_object_acl_rest(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket-name"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "bucket": "bucket-name",
                    "role": "READER",
                    "entity": "test-entity@example.com",
                }
            ),
        )
        acl = bucket.insert_default_object_acl(request, None)
        self.assertEqual(acl.role, "READER")
        self.assertEqual(acl.entity, "test-entity@example.com")
        acl = bucket.update_default_object_acl(request, "test-entity@example.com", None)
        self.assertEqual(acl.role, "READER")
        self.assertEqual(acl.entity, "test-entity@example.com")
        acl = bucket.patch_default_object_acl(request, "test-entity@example.com", None)
        self.assertEqual(acl.role, "READER")
        self.assertEqual(acl.entity, "test-entity@example.com")

    def test_invalid_ubla_and_predefined_acl(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = testbench.common.FakeRequest(
            args={"predefinedAcl": "projectPrivate"},
            data=json.dumps(
                {"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}
            ),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket.update(request, None)
        self.assertEqual(rest.exception.code, 400)

    def test_invalid_ubla_and_predefined_default_object_acl(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = testbench.common.FakeRequest(
            args={"predefinedDefaultObjectAcl": "projectPrivate"},
            data=json.dumps(
                {"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}
            ),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket.update(request, None)
        self.assertEqual(rest.exception.code, 400)

    def test_invalid_init_with_ubla_and_predefined_acl(self):
        request = testbench.common.FakeRequest(
            args={"predefinedAcl": "projectPrivate"},
            data=json.dumps(
                {
                    "name": "bucket",
                    "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
                }
            ),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(rest.exception.code, 400)

    def test_invalid_init_with_ubla_and_predefined_default_object_acl(self):
        request = testbench.common.FakeRequest(
            args={"predefinedDefaultObjectAcl": "projectPrivate"},
            data=json.dumps(
                {
                    "name": "bucket",
                    "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
                    "defaultObjectAcl": [],
                }
            ),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(rest.exception.code, 400)

    def test_rpo(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(bucket.metadata.rpo, "DEFAULT")
        request = testbench.common.FakeRequest(
            args={"bucket": "bucket"},
            data=json.dumps({"rpo": "ASYNC_TURBO"}),
        )
        bucket.patch(request, None)
        self.assertEqual(bucket.metadata.rpo, "ASYNC_TURBO")

    def test_soft_delete(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "softDeletePolicy": {"retentionDurationSeconds": 7 * 86400},
                }
            ),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        expected = duration_pb2.Duration()
        expected.FromSeconds(7 * 86400)
        self.assertEqual(
            bucket.metadata.soft_delete_policy.retention_duration, expected
        )
        self.assertNotEqual(
            bucket.metadata.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

        request = testbench.common.FakeRequest(
            args={"bucket": "bucket"},
            data=json.dumps(
                {"softDeletePolicy": {"retentionDurationSeconds": 30 * 86400}}
            ),
        )
        bucket.patch(request, None)
        expected = duration_pb2.Duration()
        expected.FromSeconds(30 * 86400)
        self.assertEqual(
            bucket.metadata.soft_delete_policy.retention_duration, expected
        )
        self.assertNotEqual(
            bucket.metadata.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

    def test_soft_delete_too_short(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "softDeletePolicy": {"retentionDurationSeconds": 1 * 86400},
                }
            ),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(rest.exception.code, 400)

    def test_soft_delete_too_long(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "softDeletePolicy": {"retentionDurationSeconds": 700 * 86400},
                }
            ),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(rest.exception.code, 400)

    def test_update_soft_delete_validates(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "softDeletePolicy": {"retentionDurationSeconds": 30 * 86400},
                }
            ),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        bucket.update(request, None)
        expected = duration_pb2.Duration()
        expected.FromSeconds(30 * 86400)
        self.assertEqual(
            bucket.metadata.soft_delete_policy.retention_duration, expected
        )
        self.assertNotEqual(
            bucket.metadata.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"softDeletePolicy": {"retentionDurationSeconds": 10}}),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket.update(request, None)
        self.assertEqual(rest.exception.code, 400)
        self.assertEqual(
            bucket.metadata.soft_delete_policy.retention_duration, expected
        )
        self.assertNotEqual(
            bucket.metadata.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {"softDeletePolicy": {"retentionDurationSeconds": 700 * 86400}}
            ),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket.update(request, None)
        self.assertEqual(rest.exception.code, 400)
        self.assertEqual(
            bucket.metadata.soft_delete_policy.retention_duration, expected
        )
        self.assertNotEqual(
            bucket.metadata.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

    def test_patch_soft_delete_validates(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "softDeletePolicy": {"retentionDurationSeconds": 30 * 86400},
                }
            ),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        bucket.update(request, None)
        expected = duration_pb2.Duration()
        expected.FromSeconds(30 * 86400)
        self.assertEqual(
            bucket.metadata.soft_delete_policy.retention_duration, expected
        )
        self.assertNotEqual(
            bucket.metadata.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"softDeletePolicy": {"retentionDurationSeconds": 10}}),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket.patch(request, None)
        self.assertEqual(rest.exception.code, 400)
        self.assertEqual(
            bucket.metadata.soft_delete_policy.retention_duration, expected
        )
        self.assertNotEqual(
            bucket.metadata.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {"softDeletePolicy": {"retentionDurationSeconds": 700 * 86400}}
            ),
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            bucket.patch(request, None)
        self.assertEqual(rest.exception.code, 400)
        self.assertEqual(
            bucket.metadata.soft_delete_policy.retention_duration, expected
        )
        self.assertNotEqual(
            bucket.metadata.soft_delete_policy.effective_time, timestamp_pb2.Timestamp()
        )

    def test_cdr(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "location": "US-EAST1+US-WEST1",
                    "storageClass": "STANDARD",
                }
            ),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(bucket.metadata.location, "US-EAST1+US-WEST1")

    def test_ip_filter(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "bucket",
                    "ipFilter": {
                        "mode": "mode",
                        "publicNetworkSource": {
                            "allowedIpCidrRanges": ["213.207.0.0/17"]
                        },
                        "vpcNetworkSources": [
                            {
                                "network": "network",
                                "allowedIpCidrRanges": ["192.168.0.0/24"],
                            }
                        ],
                        "allowCrossOrgVpcs": True,
                        "allowAllServiceAgentAccess": True,
                    },
                }
            ),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(bucket.metadata.ip_filter.mode, "mode")
        self.assertEqual(
            bucket.metadata.ip_filter.public_network_source.allowed_ip_cidr_ranges,
            ["213.207.0.0/17"],
        )
        self.assertEqual(
            bucket.metadata.ip_filter.vpc_network_sources[0].allowed_ip_cidr_ranges,
            ["192.168.0.0/24"],
        )
        self.assertEqual(
            bucket.metadata.ip_filter.vpc_network_sources[0].network, "network"
        )
        self.assertEqual(bucket.metadata.ip_filter.allow_cross_org_vpcs, True)
        self.assertEqual(bucket.metadata.ip_filter.allow_all_service_agent_access, True)


if __name__ == "__main__":
    unittest.main()
