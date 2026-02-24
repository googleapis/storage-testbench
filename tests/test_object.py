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
import datetime
import hashlib
import json
import unittest
import unittest.mock

from google.protobuf.timestamp_pb2 import Timestamp
from werkzeug.test import create_environ
from werkzeug.wrappers import Request

import gcs
import testbench
from google.storage.v2 import storage_pb2
from tests.format_multipart_upload import format_multipart_upload


class TestObject(unittest.TestCase):
    def setUp(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket"})
        )
        self.bucket, _ = gcs.bucket.Bucket.init(request, None)

    def test_init_media(self):
        request = testbench.common.FakeRequest(
            args={"name": "object"}, data=b"12345678", headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.assertEqual(blob.metadata.bucket, "projects/_/buckets/bucket")
        self.assertEqual(blob.metadata.name, "object")
        self.assertNotEqual(blob.metadata.etag, "")
        self.assertEqual(blob.media, b"12345678")

    def test_init_retention_period(self):
        retention_period = 600
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "name": "retention_bucket",
                    "retentionPolicy": {"retentionPeriod": retention_period},
                }
            ),
        )
        self.retention_bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = testbench.common.FakeRequest(
            args={"name": "object"}, data=b"12345678", headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.retention_bucket.metadata)
        expected_retention_expiration = (
            blob.metadata.create_time.ToDatetime()
            + datetime.timedelta(0, retention_period)
        )
        self.assertEqual(
            blob.metadata.retention_expire_time.ToDatetime(),
            expected_retention_expiration,
        )

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
        boundary, payload = format_multipart_upload(
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
        self.assertEqual(blob.metadata.bucket, "projects/_/buckets/bucket")
        self.assertEqual(blob.metadata.name, "object")
        self.assertEqual(blob.media, b"123456789")
        self.assertEqual(blob.metadata.metadata["key"], "value")
        self.assertEqual(blob.metadata.content_type, "image/jpeg")

    def test_object_context_lifecycle(self):
        # 1. Initialization (Multipart)
        media_content = "A journey of a thousand miles begins with a single step."
        initial_metadata = {
            "name": "quoteObject",
            "contexts": {
                "custom": {
                    "author": {"value": "Lao Tzu"},
                    "genre": {"value": "philosophy"},
                }
            },
        }
        boundary, payload = format_multipart_upload(
            initial_metadata, media=media_content, content_type="text/plain"
        )
        req = self._create_request(payload, is_multipart=True, boundary=boundary)
        blob, _ = gcs.object.Object.init_multipart(req, self.bucket.metadata)

        self.assertEqual(blob.metadata.name, "quoteObject")
        self.assertEqual(blob.media, media_content.encode("utf-8"))
        self._assert_valid_custom_context_value(blob, "author", "Lao Tzu")

        # 2. Partial Update (Patch)
        # We only change the genre; the author should persist.
        patch_req = self._create_request(
            {"contexts": {"custom": {"genre": {"value": "philo quotes"}}}}
        )
        blob.patch(patch_req, None)

        self._assert_valid_custom_context_value(blob, "genre", "philo quotes")
        self._assert_valid_custom_context_value(blob, "author", "Lao Tzu")

        # 3. Deleting a specific key via Patch
        delete_key_req = self._create_request(
            {"contexts": {"custom": {"author": None}}}
        )
        blob.patch(delete_key_req, None)

        self.assertNotIn("author", blob.metadata.contexts.custom)
        self._assert_valid_custom_context_value(blob, "genre", "philo quotes")

        # 4. Full Metadata Update
        # This should replace the existing context map entirely
        new_data = {"contexts": {"custom": {"newKey": {"value": "new value"}}}}
        update_req = self._create_request(new_data)
        blob.update(update_req, None)

        self.assertNotIn("genre", blob.metadata.contexts.custom)
        self._assert_valid_custom_context_value(blob, "newKey", "new value")

        # 5. Patching some other field should not affect existing contexts
        new_data = {"contentType": "application/json"}
        update_req = self._create_request(new_data)
        blob.patch(update_req, None)

        self.assertEqual(blob.metadata.content_type, "application/json")
        self._assert_valid_custom_context_value(blob, "newKey", "new value")

        # 6. Clear entire context map
        clear_req = self._create_request({"contexts": {"custom": None}})
        blob.patch(clear_req, None)
        self.assertFalse(blob.metadata.HasField("contexts"))

    def test_object_context_invalid_input(self):
        # Verify if the object init triggers the validation assert.
        media_content = "Abcefgh."
        initial_metadata = {
            "name": "letters",
            "contexts": {
                "custom": {
                    "google": {"value": "A google value"},
                }
            },
        }
        boundary, payload = format_multipart_upload(
            initial_metadata, media=media_content, content_type="text/plain"
        )
        req = self._create_request(payload, is_multipart=True, boundary=boundary)
        with self.assertRaises(ValueError) as context:
            gcs.object.Object.init_multipart(req, self.bucket.metadata)
        expected_error_message = "Keys cannot begin with 'goog'"
        self.assertIn(expected_error_message, str(context.exception))

        # Setup a clean object to verify the rest of validation rules with patch.
        simple_metadata = {"name": "letters"}
        boundary, payload = format_multipart_upload(
            simple_metadata, media=media_content, content_type="text/plain"
        )
        req = self._create_request(payload, is_multipart=True, boundary=boundary)
        blob, _ = gcs.object.Object.init_multipart(req, self.bucket.metadata)

        # --- Restricted Characters in Key ---
        patch_req = self._create_request(
            {"contexts": {"custom": {"my sister's name": {"value": "some values"}}}}
        )
        with self.assertRaises(ValueError) as context:
            blob.patch(patch_req, None)
        self.assertIn("contains restricted characters", str(context.exception))

        # --- Restricted Characters in Value ---
        patch_req = self._create_request(
            {"contexts": {"custom": {"validKey": {"value": "bad/value"}}}}
        )
        with self.assertRaises(ValueError) as context:
            blob.patch(patch_req, None)
        self.assertIn("contains restricted characters", str(context.exception))

        # --- Must begin with an alphanumeric character ---
        patch_req = self._create_request(
            {"contexts": {"custom": {"-badkey": {"value": "valid_value"}}}}
        )
        with self.assertRaises(ValueError) as context:
            blob.patch(patch_req, None)
        self.assertIn("must begin with an alphanumeric character", str(context.exception))

        # --- Must be 1 - 256 UTF-8 code units (Testing 257 characters) ---
        long_string = "a" * 257
        patch_req = self._create_request(
            {"contexts": {"custom": {long_string: {"value": "valid_value"}}}}
        )
        with self.assertRaises(ValueError) as context:
            blob.patch(patch_req, None)
        self.assertIn("must be between 1 and 256 UTF-8 code units", str(context.exception))

        # --- Limit to 50 entries per object (Testing 51 entries) ---
        too_many_contexts = {f"key{i}": {"value": "val"} for i in range(51)}
        patch_req = self._create_request(
            {"contexts": {"custom": too_many_contexts}}
        )
        with self.assertRaises(ValueError) as context:
            blob.patch(patch_req, None)
        self.assertIn("cannot exceed 50", str(context.exception))

    def test_init_multipart_with_acl(self):
        boundary, payload = format_multipart_upload(
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
        boundary, payload = format_multipart_upload(
            {"name": "object"},
            media="",
        )
        request = testbench.common.FakeRequest(
            args={"predefinedAcl": "projectPrivate"},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        self.bucket.metadata.iam_config.uniform_bucket_level_access.enabled = True
        with self.assertRaises(testbench.error.RestException) as rest:
            _, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(rest.exception.code, 400)

    def test_init_csek(self):
        boundary, payload = format_multipart_upload(
            {"name": "object"},
            media="",
        )
        key = b"A" * 16 + b"B" * 16
        key_sha256 = hashlib.sha256(key).digest()
        key_b64 = base64.b64encode(key)
        key_sha256_b64 = base64.b64encode(key_sha256)
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
        self.assertEqual(blob.metadata.customer_encryption.key_sha256_bytes, key_sha256)

    def test_init_multipart_missing_name(self):
        boundary, payload = format_multipart_upload(
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
        boundary, payload = format_multipart_upload(
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
        # The magic string is the MD5 hash for an empty object, computed using `gcloud storage hash`
        boundary, payload = format_multipart_upload(
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
        # The magic string is the CRC32C checksum for an empty object, computed using `gcloud storage hash`
        boundary, payload = format_multipart_upload(
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
                    # This MD5 hash was obtained using `gcloud storage hash`
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
                    # This CRC32C checksum was obtained using `gcloud storage hash`
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

    __REST_FIELDS_KEY_ONLY = [
        "owner",
        "timeCreated",
        "timeDeleted",
        "timeFinalized",
        "timeStorageClassUpdated",
        "updated",
    ]

    def test_grpc_to_rest(self):
        """Make sure that objects created by `gRPC` work with `REST`'s requests."""
        spec = storage_pb2.WriteObjectSpec(
            resource=storage_pb2.Object(
                name="test-object-name",
                bucket="bucket",
                metadata={"label0": "value0"},
                cache_control="no-cache",
                content_disposition="test-value",
                content_encoding="test-value",
                content_language="test-value",
                content_type="octet-stream",
                storage_class="regional",
                customer_encryption=storage_pb2.CustomerEncryption(
                    encryption_algorithm="AES", key_sha256_bytes=b"123456"
                ),
                custom_time=testbench.common.rest_rfc3339_to_proto(
                    "2021-08-01T12:00:00Z"
                ),
                event_based_hold=True,
                kms_key="test-value",
                retention_expire_time=testbench.common.rest_rfc3339_to_proto(
                    "2022-01-01T00:00:00Z"
                ),
                temporary_hold=True,
                delete_time=testbench.common.rest_rfc3339_to_proto(
                    "2021-06-01T00:00:00Z"
                ),
                update_storage_class_time=testbench.common.rest_rfc3339_to_proto(
                    "2021-07-01T00:00:00Z"
                ),
                contexts=storage_pb2.ObjectContexts(
                    custom={
                        "environment": storage_pb2.ObjectCustomContextPayload(
                            value="preprod",
                        ),
                    }
                ),
            )
        )
        request = storage_pb2.WriteObjectRequest(
            write_object_spec=spec,
            checksummed_data=storage_pb2.ChecksummedData(content=b"123456789"),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        db.get_bucket = unittest.mock.MagicMock(return_value=self.bucket)

        context = unittest.mock.Mock()
        context.invocation_metadata = unittest.mock.Mock(return_value=dict())

        upload, _ = gcs.upload.Upload.init_write_object_grpc(db, [request], context)
        blob, _ = gcs.object.Object.init(
            upload.request,
            upload.metadata,
            upload.media,
            upload.bucket,
            False,
            "FakeContext",
        )
        self.assertEqual(blob.metadata.bucket, "projects/_/buckets/bucket")
        self.assertEqual(blob.metadata.name, "test-object-name")
        self.assertEqual(blob.media, b"123456789")
        self.assertEqual(blob.metadata.contexts.custom["environment"].value, "preprod")

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
            "bucket/o/test-object-name/" + generation, rest_metadata.pop("id")
        )
        # Verify custom contexts.
        custom_contexts = rest_metadata.pop("contexts", None)
        self.assertIsNotNone(custom_contexts)
        self.assertEqual(custom_contexts["custom"]["environment"]["value"], "preprod")
        self.assertTrue(custom_contexts["custom"]["environment"]["createTime"])
        self.assertTrue(custom_contexts["custom"]["environment"]["updateTime"])

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
                "customTime": "2021-08-01T12:00:00Z",
                "eventBasedHold": True,
                "crc32c": "4waSgw==",
                "customerEncryption": {
                    "encryptionAlgorithm": "AES",
                    "keySha256": "MTIzNDU2",  # base64.b64encode("123456")
                },
                "kmsKeyName": "test-value",
                "md5Hash": "JfnnlDI7RTiF9RgfG2JNCw==",
                "metadata": {
                    "label0": "value0",
                    # The testbench adds useful annotations
                    "x_emulator_upload": "grpc",
                    "x_emulator_no_crc32c": "true",
                    "x_emulator_no_md5": "true",
                    "x_testbench_upload": "grpc",
                    "x_testbench_no_crc32c": "true",
                    "x_testbench_no_md5": "true",
                },
                "metageneration": "1",
                "etag": blob.metadata.etag,
                "retentionExpirationTime": "2022-01-01T00:00:00Z",
                "size": "9",
                "storageClass": "regional",
                "temporaryHold": True,
            },
        )

        # `REST` PATCH

        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps(
                {
                    "metadata": {"method": "rest"},
                    "contexts": {"custom": {"environment": {"value": "prod"}}},
                }
            ),
        )
        blob.patch(request, None)
        self.assertEqual(blob.metadata.metadata["method"], "rest")
        self.assertEqual(blob.metadata.contexts.custom["environment"].value, "prod")

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
            "contexts": {"custom": {"environment": {"value": "autopush"}}},
            "eventBasedHold": True,
            "customerEncryption": {
                "encryptionAlgorithm": "AES",
                # base64.b64encode("123456").decode("utf-8"),
                "keySha256": "MTIzNDU2",
            },
            "kmsKeyName": "test-value",
            "retentionExpirationTime": "2022-01-01T00:00:00Z",
            "temporaryHold": True,
            # These are a bit artificial, but good to test the
            # testbench preserves valid fields.
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
        self.assertEqual(blob.metadata.bucket, "projects/_/buckets/bucket")
        self.assertEqual(blob.metadata.name, "test-object-name")
        self.assertEqual(blob.media, b"123456789")
        self.assertEqual(blob.metadata.metadata["method"], "rest")
        self.assertEqual(blob.metadata.contexts.custom["environment"].value, "autopush")

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
            "bucket/o/test-object-name/" + generation, rest_metadata.pop("id")
        )
        custom_contexts = rest_metadata.pop("contexts", None)
        self.assertIsNotNone(custom_contexts)
        self.assertEqual(custom_contexts["custom"]["environment"]["value"], "autopush")
        self.assertTrue(custom_contexts["custom"]["environment"]["createTime"])
        self.assertTrue(custom_contexts["custom"]["environment"]["updateTime"])

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
                    "keySha256": "MTIzNDU2",
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
                "etag": blob.metadata.etag,
                "retentionExpirationTime": "2022-01-01T00:00:00Z",
                "size": "9",
                "storageClass": "regional",
                "temporaryHold": True,
            },
        )

    def test_update_and_patch(self):
        # Because Object's `update` and `patch` are similar to Bucket'ones, we only
        # want to make sure that REST `UPDATE` and `PATCH` does not throw any exception.

        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=foo_bar_baz"},
            data=b'--foo_bar_baz\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{"name": "object", "metadata": {"method": "rest"}}\r\n--foo_bar_baz\r\nContent-Type: image/jpeg\r\n\r\n123456789\r\n--foo_bar_baz--\r\n',
            environ={},
        )
        blob, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)
        self.assertEqual(blob.metadata.name, "object")
        self.assertEqual(blob.metadata.metadata["method"], "rest")
        self.assertEqual(blob.metadata.content_type, "image/jpeg")

        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"metadata": {"method": "rest_update"}})
        )
        blob.update(request, None)
        self.assertEqual(blob.metadata.metadata["method"], "rest_update")
        # Modifiable fields will be replaced by default value when updating
        self.assertEqual(blob.metadata.content_type, "")

        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"metadata": {"method": "rest_patch"}})
        )
        blob.patch(request, None)
        self.assertEqual(blob.metadata.metadata["method"], "rest_patch")

    def test_acl_crud(self):
        boundary, payload = format_multipart_upload(
            {"name": "object"},
            media="",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        blob, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)
        request = testbench.common.FakeRequest(
            args={},
            headers={},
            # The actual format for "entity" is more complex, but for testing any string will do.
            data=json.dumps({"entity": "test-entity", "role": "READER"}),
            environ={},
        )
        insert_result = blob.insert_acl(request, None)
        self.assertEqual(insert_result.entity, "test-entity")
        self.assertEqual(insert_result.role, "READER")
        get_result = blob.get_acl("test-entity", None)
        self.assertEqual(get_result, insert_result)

        request = testbench.common.FakeRequest(
            args={},
            headers={},
            data=json.dumps({"entity": "test-entity", "role": "OWNER"}),
            environ={},
        )
        update_result = blob.update_acl(request, "test-entity", None)
        self.assertEqual(update_result.entity, "test-entity")
        self.assertEqual(update_result.role, "OWNER")

        request = testbench.common.FakeRequest(
            args={},
            headers={},
            data=json.dumps({"entity": "test-entity", "role": "READER"}),
            environ={},
        )
        patch_result = blob.patch_acl(request, "test-entity", None)
        self.assertEqual(patch_result.entity, "test-entity")
        self.assertEqual(patch_result.role, "READER")

        blob.delete_acl("test-entity", None)
        with self.assertRaises(testbench.error.RestException) as rest:
            blob.get_acl("test-entity", None)
        self.assertEqual(rest.exception.code, 404)

    def test_rest_media(self):
        boundary, payload = format_multipart_upload(
            {"name": "object"},
            media="How vexingly quick daft zebras jump!",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        blob, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)
        request = Request(
            create_environ(
                base_url="http://localhost:8080",
                headers={},
                data=json.dumps({}),
            )
        )
        response = blob.rest_media(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"How vexingly quick daft zebras jump!")
        self.assertIn("x-goog-hash", response.headers)
        self.assertIn("x-goog-generation", response.headers)
        self.assertIn("x-goog-metageneration", response.headers)
        self.assertIn("x-goog-storage-class", response.headers)
        self.assertIn("Content-Length", response.headers)
        self.assertEqual(response.headers["Content-Length"], str(len(blob.media)))

        cases = {
            "bytes=4-9": (b"vexing", "4-9"),
            "bytes=12-": (b" quick daft zebras jump!", "12-35"),
            "bytes=-5": (b"jump!", "31-35"),
        }
        for range, expected in cases.items():
            expected_data, expected_range = expected
            request = Request(
                create_environ(
                    base_url="http://localhost:8080",
                    headers={"range": range},
                    data=json.dumps({}),
                )
            )
            response = blob.rest_media(request)
            self.assertEqual(response.status_code, 206)
            self.assertEqual(response.data, expected_data)
            self.assertIn("content-range", response.headers)
            content_range = response.headers["content-range"]
            self.assertEqual(
                content_range,
                "bytes %s/%d" % (expected_range, len(blob.media)),
                msg="unexpected content-range header: " + content_range,
            )
        # Test raises 416 if request range cannot be satisfied.
        request = Request(
            create_environ(
                base_url="http://localhost:8080",
                headers={"range": "bytes=36-"},
                data=json.dumps({}),
            )
        )
        with self.assertRaises(testbench.error.RestException) as rest:
            response = blob.rest_media(request)
        self.assertEqual(rest.exception.code, 416)

    def test_rest_media_instructions(self):
        boundary, payload = format_multipart_upload(
            {"name": "object"},
            media="How vexingly quick daft zebras jump!",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        blob, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)

        retry_cases = {
            "return-503-after-256K/retry-1": 503,
            "return-503-after-256K/retry-2": 503,
            "return-503-after-256K/retry-3": 200,
        }
        for instruction, status_code in retry_cases.items():
            request = Request(
                create_environ(
                    base_url="http://localhost:8080",
                    headers={
                        "x-goog-testbench-instructions": instruction,
                        "range": "bytes=2-",
                    },
                    data=json.dumps({}),
                )
            )
            response = blob.rest_media(request)
            self.assertEqual(response.status_code, status_code, msg=instruction)

            request = testbench.common.FakeRequest.init_xml(request)
            response = blob.rest_media(request)
            self.assertEqual(
                response.status_code, status_code, msg="XML " + instruction
            )

        request = Request(
            create_environ(
                base_url="http://localhost:8080",
                headers={"x-goog-testbench-instructions": "return-corrupted-data"},
                data=json.dumps({}),
            )
        )
        response = blob.rest_media(request)
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.data, b"How vexingly quick daft zebras jump!")

        request = testbench.common.FakeRequest.init_xml(request)
        response = blob.rest_media(request)
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.data, b"How vexingly quick daft zebras jump!")

        cases = {
            "return-broken-stream": 200,
            "return-503-after-256K": 200,
            "return-503-after-256K/retry-3": 200,
            "stall-at-256KiB": 200,
        }
        for instruction, status_code in cases.items():
            request = Request(
                create_environ(
                    base_url="http://localhost:8080",
                    headers={"x-goog-testbench-instructions": instruction},
                    data=json.dumps({}),
                )
            )
            response = blob.rest_media(request)
            self.assertEqual(response.status_code, status_code, msg=instruction)
            self.assertEqual(
                response.data,
                b"How vexingly quick daft zebras jump!",
                msg=instruction,
            )

            request = testbench.common.FakeRequest.init_xml(request)
            response = blob.rest_media(request)
            self.assertEqual(
                response.status_code, status_code, msg="XML " + instruction
            )
            self.assertEqual(
                response.data,
                b"How vexingly quick daft zebras jump!",
                msg="XML " + instruction,
            )

    def test_stall_always(self):
        boundary, payload = format_multipart_upload(
            {"name": "object"},
            media="How vexingly quick daft zebras jump!",
        )
        request = testbench.common.FakeRequest(
            args={},
            headers={"content-type": "multipart/related; boundary=" + boundary},
            data=payload.encode("utf-8"),
            environ={},
        )
        blob, _ = gcs.object.Object.init_multipart(request, self.bucket.metadata)
        request = Request(
            create_environ(
                base_url="http://localhost:8080",
                headers={"x-goog-testbench-instructions": "stall-always"},
                data=json.dumps({}),
            )
        )
        mock_sleep = unittest.mock.create_autospec(lambda x: None)
        response = blob.rest_media(request, delay=mock_sleep)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"How vexingly quick daft zebras jump!")
        mock_sleep.assert_called_once_with(10)

    def _assert_valid_custom_context_value(self, blob, key, expected_value):
        self.assertIn(key, blob.metadata.contexts.custom)
        self.assertEqual(blob.metadata.contexts.custom[key].value, expected_value)
        self.assertGreater(
            blob.metadata.contexts.custom[key].create_time.ToSeconds(), 0
        )
        self.assertGreater(
            blob.metadata.contexts.custom[key].update_time.ToSeconds(), 0
        )

    def _create_request(self, data, is_multipart=False, boundary=None):
        """Helper to generate consistent fake requests."""
        headers = {}
        if is_multipart:
            headers["content-type"] = f"multipart/related; boundary={boundary}"
            payload = data.encode("utf-8")
        else:
            payload = json.dumps(data)

        return testbench.common.FakeRequest(
            args={}, headers=headers, data=payload, environ={}
        )


if __name__ == "__main__":
    unittest.main()
