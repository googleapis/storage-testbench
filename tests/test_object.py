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

"""Tests for the Object class (see gcs/object.py)."""

import base64
import hashlib
import json
import unittest

from werkzeug.test import create_environ
from werkzeug.wrappers import Request
from google.cloud.storage_v1.proto import storage_pb2 as storage_pb2
from google.cloud.storage_v1.proto import storage_resources_pb2 as resources_pb2
from google.cloud.storage_v1.proto.storage_resources_pb2 import CommonEnums

import gcs
import testbench


class TestObject(unittest.TestCase):
    def setUp(self):
        request = storage_pb2.InsertBucketRequest(bucket={"name": "bucket"})
        bucket, _ = gcs.bucket.Bucket.init(request, "")
        self.bucket = bucket

    @staticmethod
    def __format_multipart_upload(
        metadata, media, content_type="application/octet-stream"
    ):
        boundary = "test_separator_deadbeef"
        payload = (
            ("--" + boundary + "\r\n").join(
                [
                    "",
                    # object metadata "part"
                    "\r\n".join(
                        [
                            "Content-Type: application/json; charset=UTF-8",
                            "",
                            json.dumps(metadata),
                            "",
                        ]
                    ),
                    # object media "part"
                    "\r\n".join(
                        [
                            "Content-Type: " + content_type,
                            "Content-Length: %d" % len(media),
                            "",
                            media,
                            "",
                        ]
                    ),
                ]
            )
            + "--"
            + boundary
            + "--\r\n"
        )
        return boundary, payload

    def test_init_media(self):
        request = testbench.common.FakeRequest(
            args={"name": "object"}, data=b"12345678", headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.assertEqual(blob.metadata.name, "object")
        self.assertEqual(blob.media, b"12345678")

    def test_init_and_corrupt_media(self):
        """Sometimes we want the testbench to inject errors, to make sure the librar(ies) detects them."""
        request = testbench.common.FakeRequest(
            args={"name": "object"},
            data=b"12345678",
            headers={"x-goog-testbench-instructions": "inject-upload-data-error"},
            environ={},
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.assertEqual(blob.metadata.name, "object")
        self.assertNotEqual(blob.media, b"12345678")

    def test_init_multipart(self):
        boundary, payload = self.__format_multipart_upload(
            {"name": "object", "metadata": {"key": "value"}},
            media="123456789",
            content_type="image/jpeg",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        blob, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(blob.metadata.name, "object")
        self.assertEqual(blob.media, b"123456789")
        self.assertEqual(blob.metadata.metadata["key"], "value")
        self.assertEqual(blob.metadata.content_type, "image/jpeg")

    def test_init_multipart_with_acl(self):
        boundary, payload = self.__format_multipart_upload(
            {
                "name": "object",
                "acl": [{"entity": "allAuthenticatedUsers", "role": "READER"}],
            },
            media="",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        blob, projection = gcs.object.Object.init_multipart(
            request, self.bucket.metadata
        )
        self.assertEqual(blob.metadata.name, "object")
        self.assertEqual(blob.media, b"")
        entities = {a.entity for a in blob.metadata.acl}
        self.assertIn("allAuthenticatedUsers", entities)
        self.assertEqual(projection, "full")

    def test_init_mismatched_ubla_and_predefined_acl(self):
        boundary, payload = self.__format_multipart_upload(
            {"name": "object"},
            media="",
        )
        request = testbench.common.FakeRequest(
            args={"predefinedAcl": "projectPrivate"},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        self.bucket.metadata.iam_configuration.uniform_bucket_level_access.enabled = (
            True
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            _, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(rest.exception.code, 400)

    def test_init_csek(self):
        boundary, payload = self.__format_multipart_upload(
            {"name": "object"},
            media="",
        )
        key_b64 = base64.b64encode(b"X" * 32)
        key_sha256_b64 = base64.b64encode(hashlib.sha256(b"X" * 32).digest())
        request = testbench.common.FakeRequest(
            args={},
            headers={
                "content-type": "multipart/related; boundary=" + boundary,
                "x-goog-encryption-algorithm": "AES256",
                "x-goog-encryption-key": key_b64,
                "x-goog-encryption-key-sha256": key_sha256_b64,
            },
            data=payload.encode("utf-8"),
            environ={},
        )
        blob, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(blob.metadata.name, "object")
        self.assertEqual(blob.media, b"")
        self.assertEqual(
            blob.metadata.customer_encryption.encryption_algorithm, "AES256"
        )
        self.assertEqual(
            blob.metadata.customer_encryption.key_sha256, key_sha256_b64.decode("utf-8")
        )

    def test_init_multipart_missing_name(self):
        boundary, payload = self.__format_multipart_upload(
            {"not-the-name": "object"},
            media="",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(rest.exception.code, 400)

    def test_init_multipart_inconsistent_content_type(self):
        boundary, payload = self.__format_multipart_upload(
            {"name": "object", "contentType": "text/plain"},
            media="How vexingly quick daft zebras jump!",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(rest.exception.code, 412)

    def test_init_multipart_inconsistent_md5(self):
        # The magic string is the MD5 hash for an empty object, computed using `gsutil hash`
        boundary, payload = self.__format_multipart_upload(
            {"name": "object", "md5Hash": "1B2M2Y8AsgTpgAmY7PhCfg=="},
            "How vexingly quick daft zebras jump!",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(rest.exception.code, 412)

    def test_init_multipart_inconsistent_crc32c(self):
        # The magic string is the CRC32C checksum for an empty object, computed using `gsutil hash`
        boundary, payload = self.__format_multipart_upload(
            {"name": "object", "crc32c": "AAAAAA=="},
            "How vexingly quick daft zebras jump!",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(rest.exception.code, 412)

    def test_init_xml_md5hash(self):
        media = b"The quick brown fox jumps over the lazy dog"
        request = Request(
            create_environ(
                base_url="http://localhost:8080",
                content_type="text/plain",
                headers={
                    # This MD5 hash was obtained using `gsutil hash`
                    "x-goog-hash": "md5=nhB9nTcrtoJr2B01QqQZ1g==",
                },
                content_length=len(media),
                data=media,
            )
        )
        blob, _ = gcs.object.Object.init_xml(request, self.bucket.metadata, "object")
        self.assertEqual(blob.metadata.name, "object")
        self.assertEqual(blob.media, b"The quick brown fox jumps over the lazy dog")
        self.assertEqual(blob.metadata.content_type, "text/plain")

    def test_init_xml_crc32c(self):
        media = b"The quick brown fox jumps over the lazy dog"
        request = Request(
            create_environ(
                base_url="http://localhost:8080",
                content_type="text/plain",
                headers={
                    # This CRC32C checksum was obtained using `gsutil hash`
                    "x-goog-hash": "crc32c=ImIEBA==",
                },
                content_length=len(media),
                data=media,
            )
        )
        blob, _ = gcs.object.Object.init_xml(request, self.bucket.metadata, "object")
        self.assertEqual(blob.metadata.name, "object")
        self.assertEqual(blob.media, b"The quick brown fox jumps over the lazy dog")
        self.assertEqual(blob.metadata.content_type, "text/plain")

    def test_init_predefined_acl(self):
        boundary, payload = self.__format_multipart_upload(
            {"name": "object"},
            media="",
        )
        request = testbench.common.FakeRequest(
            args={"predefinedAcl": ""},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        blob, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)

    __REST_FIELDS_KEY_ONLY = [
        "owner",
        "timeCreated",
        "timeDeleted",
        "timeStorageClassUpdated",
        "updated",
    ]

    def test_grpc_to_rest(self):
        # Make sure that object created by `gRPC` works with `REST`'s request.
        spec = storage_pb2.InsertObjectSpec(
            resource=resources_pb2.Object(
                name="test-object-name",
                bucket="bucket",
                metadata={"label0": "value0"},
                cache_control="no-cache",
                content_disposition="test-value",
                content_encoding="test-value",
                content_language="test-value",
                content_type="octet-stream",
                storage_class="regional",
                customer_encryption=resources_pb2.Object.CustomerEncryption(
                    encryption_algorithm="AES", key_sha256="123456"
                ),
                # TODO(#6982) - add these fields when moving to storage/v2
                #   custom_time=testbench.common.rest_rfc3339_to_proto("2021-08-01T12:00:00Z"),
                event_based_hold={"value": True},
                kms_key_name="test-value",
                retention_expiration_time=testbench.common.rest_rfc3339_to_proto(
                    "2022-01-01T00:00:00Z"
                ),
                temporary_hold=True,
                time_deleted=testbench.common.rest_rfc3339_to_proto(
                    "2021-06-01T00:00:00Z"
                ),
                time_storage_class_updated=testbench.common.rest_rfc3339_to_proto(
                    "2021-07-01T00:00:00Z"
                ),
            )
        )
        request = storage_pb2.StartResumableWriteRequest(insert_object_spec=spec)
        upload = gcs.holder.DataHolder.init_resumable_grpc(
            request, self.bucket.metadata, ""
        )
        blob, _ = gcs.object.Object.init(
            upload.request, upload.metadata, b"123456789", upload.bucket, False, ""
        )
        self.assertDictEqual(blob.rest_only, {})
        self.assertEqual(blob.metadata.bucket, "bucket")
        self.assertEqual(blob.metadata.name, "test-object-name")
        self.assertEqual(blob.media, b"123456789")

        # `REST` GET

        rest_metadata = blob.rest_metadata()
        self.assertEqual(rest_metadata["bucket"], "bucket")
        self.assertEqual(rest_metadata["name"], "test-object-name")
        self.assertIsNone(blob.metadata.metadata.get("method"))
        # Verify the ObjectAccessControl entries have the desired fields
        acl = rest_metadata.pop("acl", None)
        self.assertIsNotNone(acl)
        for entry in acl:
            self.assertEqual(entry.pop("kind", None), "storage#objectAccessControl")
            self.assertEqual(entry.pop("bucket", None), "bucket")
            self.assertEqual(entry.pop("object", None), "test-object-name")
            self.assertIsNotNone(entry.pop("entity", None))
            self.assertIsNotNone(entry.pop("role", None))
            # Verify the remaining keys are a subset of the expected keys
            self.assertLessEqual(
                set(entry.keys()),
                set(
                    [
                        "id",
                        "selfLink",
                        "generation",
                        "email",
                        "entityId",
                        "domain",
                        "projectTeam",
                        "etag",
                    ]
                ),
            )
        # Some fields we only care that they exist.
        for key in self.__REST_FIELDS_KEY_ONLY:
            self.assertIsNotNone(rest_metadata.pop(key, None), msg="key=%s" % key)
        # Some fields we need to manually extract to check their values
        generation = rest_metadata.pop("generation", None)
        self.assertIsNotNone(generation)
        self.assertEqual(
            "bucket/o/test-object-name#" + generation, rest_metadata.pop("id")
        )
        self.maxDiff = None
        self.assertDictEqual(
            rest_metadata,
            {
                "kind": "storage#object",
                "bucket": "bucket",
                "name": "test-object-name",
                "cacheControl": "no-cache",
                "contentDisposition": "test-value",
                "contentEncoding": "test-value",
                "contentLanguage": "test-value",
                "contentType": "octet-stream",
                "eventBasedHold": True,
                "crc32c": "4waSgw==",
                "customerEncryption": {
                    "encryptionAlgorithm": "AES",
                    "keySha256": "123456",
                },
                "kmsKeyName": "test-value",
                "md5Hash": "JfnnlDI7RTiF9RgfG2JNCw==",
                "metadata": {
                    "label0": "value0",
                    # The emulator adds useful annotations
                    "x_emulator_upload": "resumable",
                    "x_emulator_no_crc32c": "true",
                    "x_emulator_no_md5": "true",
                    "x_testbench_upload": "resumable",
                    "x_testbench_no_crc32c": "true",
                    "x_testbench_no_md5": "true",
                },
                "metageneration": "1",
                "retentionExpirationTime": "2022-01-01T00:00:00Z",
                "size": "9",
                "storageClass": "regional",
                "temporaryHold": True,
            },
        )

    def test_rest_to_grpc(self):
        # Make sure that object created by `REST` works with `gRPC`'s request.
        metadata = {
            "bucket": "bucket",
            "name": "test-object-name",
            "metadata": {"method": "rest", "label0": "value0"},
            "cacheControl": "no-cache",
            "contentDisposition": "test-value",
            "contentEncoding": "test-value",
            "contentLanguage": "test-value",
            "contentType": "application/octet-stream",
            "eventBasedHold": True,
            "customerEncryption": {"encryptionAlgorithm": "AES", "keySha256": "123456"},
            "kmsKeyName": "test-value",
            "retentionExpirationTime": "2022-01-01T00:00:00Z",
            "temporaryHold": True,
            # These are a bit artificial, but good to test the
            # emulator preserves valid fields.
            "timeDeleted": "2021-07-01T01:02:03Z",
            "timeStorageClassUpdated": "2021-07-01T02:03:04Z",
            "storageClass": "regional",
        }
        boundary = "test_separator_deadbeef"
        payload = (
            ("--" + boundary + "\r\n").join(
                [
                    "",
                    # object metadata "part"
                    "\r\n".join(
                        [
                            "Content-Type: application/json; charset=UTF-8",
                            "",
                            json.dumps(metadata),
                            "",
                        ]
                    ),
                    # object media "part"
                    "\r\n".join(
                        [
                            "Content-Type: application/octet-stream",
                            "Content-Length: 9",
                            "",
                            "123456789",
                            "",
                        ]
                    ),
                ]
            )
            + "--"
            + boundary
            + "--\r\n"
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("UTF-8"),
            environ={},
        )
        blob, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(blob.metadata.bucket, "bucket")
        self.assertEqual(blob.metadata.name, "test-object-name")
        self.assertEqual(blob.media, b"123456789")
        self.assertEqual(blob.metadata.metadata["method"], "rest")
        rest_metadata = blob.rest_metadata()
        # Verify the ObjectAccessControl entries have the desired fields
        acl = rest_metadata.pop("acl", None)
        self.assertIsNotNone(acl)
        for entry in acl:
            self.assertEqual(entry.pop("kind", None), "storage#objectAccessControl")
            self.assertEqual(entry.pop("bucket", None), "bucket")
            self.assertEqual(entry.pop("object", None), "test-object-name")
            self.assertIsNotNone(entry.pop("entity", None))
            self.assertIsNotNone(entry.pop("role", None))
            # Verify the remaining keys are a subset of the expected keys
            self.assertLessEqual(
                set(entry.keys()),
                set(
                    [
                        "id",
                        "selfLink",
                        "generation",
                        "email",
                        "entityId",
                        "domain",
                        "projectTeam",
                        "etag",
                    ]
                ),
            )
        # Some fields we only care that they exist.
        for key in self.__REST_FIELDS_KEY_ONLY:
            self.assertIsNotNone(rest_metadata.pop(key, None), msg="key=%s" % key)
        # Some fields we need to manually extract to check their values
        generation = rest_metadata.pop("generation", None)
        self.assertIsNotNone(generation)
        self.assertEqual(
            "bucket/o/test-object-name#" + generation, rest_metadata.pop("id")
        )
        self.maxDiff = None
        self.assertDictEqual(
            rest_metadata,
            {
                "kind": "storage#object",
                "bucket": "bucket",
                "name": "test-object-name",
                "cacheControl": "no-cache",
                "contentDisposition": "test-value",
                "contentEncoding": "test-value",
                "contentLanguage": "test-value",
                "contentType": "application/octet-stream",
                "eventBasedHold": True,
                "crc32c": "4waSgw==",
                "customerEncryption": {
                    "encryptionAlgorithm": "AES",
                    "keySha256": "123456",
                },
                "kmsKeyName": "test-value",
                "md5Hash": "JfnnlDI7RTiF9RgfG2JNCw==",
                "metadata": {
                    "label0": "value0",
                    "method": "rest",
                    "x_emulator_upload": "multipart",
                    "x_testbench_upload": "multipart",
                },
                "metageneration": "1",
                "retentionExpirationTime": "2022-01-01T00:00:00Z",
                "size": "9",
                "storageClass": "regional",
                "temporaryHold": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
