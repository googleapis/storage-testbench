#!/usr/bin/env python3
#
# Copyright 2022 Google LLC
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

"""Unit test for proto2rest."""

import unittest

from google.storage.v2 import storage_pb2

import testbench


class TestProto2Rest(unittest.TestCase):
    def test_bucket_access_control_as_rest(self):
        acl = storage_pb2.BucketAccessControl(
            id="test-id",
            entity="test-entity",
            entity_id="test-entity-id",
            role="test-role",
            email="test-email",
            domain="test-domain",
            project_team=storage_pb2.ProjectTeam(
                project_number="12345", team="test-team"
            ),
            etag="test-only-etag",
        )
        actual = testbench.proto2rest.bucket_access_control_as_rest(
            "test-bucket-id", acl
        )
        expected = {
            "kind": "storage#bucketAccessControl",
            "id": "test-id",
            "bucket": "test-bucket-id",
            "entity": "test-entity",
            "role": "test-role",
            "email": "test-email",
            "domain": "test-domain",
            "projectTeam": {"projectNumber": "12345", "team": "test-team"},
            "etag": "test-only-etag",
        }
        self.assertEqual(actual, {**actual, **expected})

    def test_default_object_access_control_as_rest(self):
        acl = storage_pb2.ObjectAccessControl(
            id="test-id",
            entity="test-entity",
            entity_id="test-entity-id",
            role="test-role",
            email="test-email",
            domain="test-domain",
            project_team=storage_pb2.ProjectTeam(
                project_number="12345", team="test-team"
            ),
            etag="test-only-etag",
        )
        actual = testbench.proto2rest.default_object_access_control_as_rest(
            "test-bucket-id", acl
        )
        expected = {
            "kind": "storage#objectAccessControl",
            "id": "test-id",
            "bucket": "test-bucket-id",
            "entity": "test-entity",
            "role": "test-role",
            "email": "test-email",
            "domain": "test-domain",
            "projectTeam": {"projectNumber": "12345", "team": "test-team"},
            "etag": "test-only-etag",
        }
        self.assertEqual(actual, {**actual, **expected})

    def test_object_as_rest(self):
        media = b"The quick brown fox jumps over the lazy dog"
        # These checksums can be obtained using `gsutil hash`
        crc32c = "ImIEBA=="
        md5 = "nhB9nTcrtoJr2B01QqQZ1g=="
        object = storage_pb2.Object(
            name="test-object-name",
            bucket="test-bucket-id",
            generation=123,
            metageneration=234,
            etag="test-only-etag-234",
            storage_class="regional",
            size=34000,
            content_encoding="test-content-encoding",
            content_disposition="test-content-disposition",
            cache_control="test-cache-control",
            acl=[
                storage_pb2.ObjectAccessControl(
                    entity="test-entity0", role="test-role0", etag="test-only-etag0"
                ),
                storage_pb2.ObjectAccessControl(
                    entity="test-entity1", role="test-role1", etag="test-only-etag1"
                ),
            ],
            content_language="test-content-language",
            delete_time=testbench.common.rest_rfc3339_to_proto("2020-01-01T00:00:00Z"),
            content_type="octet-stream",
            create_time=testbench.common.rest_rfc3339_to_proto("2022-01-01T00:00:00Z"),
            component_count=456,
            checksums=storage_pb2.ObjectChecksums(
                crc32c=testbench.common.rest_crc32c_to_proto(crc32c),
                md5_hash=testbench.common.rest_md5_to_proto(md5),
            ),
            update_time=testbench.common.rest_rfc3339_to_proto("2023-01-01T00:00:00Z"),
            kms_key="test-kms-key",
            update_storage_class_time=testbench.common.rest_rfc3339_to_proto(
                "2024-01-01T00:00:00Z"
            ),
            temporary_hold=True,
            retention_expire_time=testbench.common.rest_rfc3339_to_proto(
                "2025-01-01T00:00:00Z"
            ),
            metadata={"label0": "value0"},
            event_based_hold=True,
            owner=storage_pb2.Owner(
                entity="test-owner-entity", entity_id="test-owner-entity-id"
            ),
            customer_encryption=storage_pb2.CustomerEncryption(
                encryption_algorithm="AES", key_sha256_bytes=b"123456"
            ),
            custom_time=testbench.common.rest_rfc3339_to_proto("2026-01-01T00:00:00Z"),
        )
        actual = testbench.proto2rest.object_as_rest(object)
        expected = {
            "kind": "storage#object",
            "name": "test-object-name",
            "bucket": "test-bucket-id",
            "generation": "123",
            "id": "test-bucket-id/o/test-object-name/123",
            "metageneration": "234",
            "etag": "test-only-etag-234",
            "storageClass": "regional",
            "size": "34000",
            "contentEncoding": "test-content-encoding",
            "contentDisposition": "test-content-disposition",
            "cacheControl": "test-cache-control",
            "acl": [
                {
                    "kind": "storage#objectAccessControl",
                    "bucket": "test-bucket-id",
                    "object": "test-object-name",
                    "generation": "123",
                    "entity": "test-entity0",
                    "role": "test-role0",
                    "etag": "test-only-etag0",
                },
                {
                    "kind": "storage#objectAccessControl",
                    "bucket": "test-bucket-id",
                    "object": "test-object-name",
                    "generation": "123",
                    "entity": "test-entity1",
                    "role": "test-role1",
                    "etag": "test-only-etag1",
                },
            ],
            "contentLanguage": "test-content-language",
            "timeDeleted": "2020-01-01T00:00:00Z",
            "contentType": "octet-stream",
            "timeCreated": "2022-01-01T00:00:00Z",
            "componentCount": 456,
            "crc32c": crc32c,
            "md5Hash": md5,
            "updated": "2023-01-01T00:00:00Z",
            "kmsKeyName": "test-kms-key",
            "timeStorageClassUpdated": "2024-01-01T00:00:00Z",
            "temporaryHold": True,
            "retentionExpirationTime": "2025-01-01T00:00:00Z",
            "metadata": {
                "label0": "value0",
            },
            "eventBasedHold": True,
            "owner": {
                "entity": "test-owner-entity",
                "entityId": "test-owner-entity-id",
            },
            "customerEncryption": {
                "encryptionAlgorithm": "AES",
                "keySha256": "MTIzNDU2",  # base64.b64encode("123456")
            },
            "customTime": "2026-01-01T00:00:00Z",
        }

        self.maxDiff = None
        self.assertEqual(actual, expected)

    def test_object_access_control_as_rest(self):
        input = storage_pb2.ObjectAccessControl(
            entity="test-entity0", role="test-role0", etag="test-only-etag0"
        )
        expected = {
            "kind": "storage#objectAccessControl",
            "bucket": "test-bucket-id",
            "object": "test-object-name",
            "generation": "123",
            "entity": "test-entity0",
            "role": "test-role0",
            "etag": "test-only-etag0",
        }
        actual = testbench.proto2rest.object_access_control_as_rest(
            "test-bucket-id", "test-object-name", "123", input
        )
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
