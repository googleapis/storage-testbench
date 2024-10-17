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
import copy
import hashlib
import json
import unittest
import unittest.mock

import crc32c
import flask
import grpc
from werkzeug.test import create_environ
from werkzeug.wrappers import Request

import gcs
import testbench
from google.storage.v2 import storage_pb2


class TestHolder(unittest.TestCase):
    def mock_context(self):
        context = unittest.mock.Mock()
        context.invocation_metadata = unittest.mock.Mock(return_value=dict())
        return context

    def test_init_resumable_rest_incorrect_usage(self):
        bucket_metadata = json.dumps({"name": "bucket-test"})
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=len(bucket_metadata),
            data=bucket_metadata,
            content_type="application/json",
            method="POST",
        )

        bucket, _ = gcs.bucket.Bucket.init(Request(environ), None)
        bucket = bucket.metadata
        with self.assertRaises(testbench.error.RestException) as cm:
            data = "{}"
            environ = create_environ(
                base_url="http://localhost:8080",
                content_length=len(data),
                data=data,
                content_type="application/json",
                method="POST",
            )
            upload = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)
        self.assertIn("No object name is invalid.", cm.exception.msg)

        with self.assertRaises(testbench.error.RestException) as cm:
            data = ""
            environ = create_environ(
                base_url="http://localhost:8080",
                content_length=len(data),
                data=data,
                content_type="application/json",
                method="POST",
            )
            upload = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)
        self.assertIn("No object name is invalid.", cm.exception.msg)

        with self.assertRaises(testbench.error.RestException) as cm:
            data = json.dumps({"name": ""})
            environ = create_environ(
                base_url="http://localhost:8080",
                query_string={"name": ""},
                content_length=len(data),
                data=data,
                content_type="application/json",
                method="POST",
            )
            _ = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)
        self.assertIn("No object name is invalid.", cm.exception.msg)

        with self.assertRaises(testbench.error.RestException) as cm:
            data = json.dumps({"name": "a"})
            environ = create_environ(
                base_url="http://localhost:8080",
                query_string={"name": "b"},
                content_length=len(data),
                data=data,
                content_type="application/json",
                method="POST",
            )
            _ = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)
        self.assertIn(
            "Value 'a' in content does not agree with value 'b'. is invalid.",
            cm.exception.msg,
        )

        with self.assertRaises(testbench.error.RestException) as cm:
            data = json.dumps({"name": ""})
            environ = create_environ(
                base_url="http://localhost:8080",
                query_string={"name": "b"},
                content_length=len(data),
                data=data,
                content_type="application/json",
                method="POST",
            )
            _ = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)
        self.assertIn(
            "Value '' in content does not agree with value 'b'. is invalid.",
            cm.exception.msg,
        )

        with self.assertRaises(testbench.error.RestException) as cm:
            data = json.dumps({"name": "a"})
            environ = create_environ(
                base_url="http://localhost:8080",
                query_string={"name": ""},
                content_length=len(data),
                data=data,
                content_type="application/json",
                method="POST",
            )
            upload = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)
        self.assertIn(
            "Value 'a' in content does not agree with value ''. is invalid.",
            cm.exception.msg,
        )

    def test_init_resumable_rest_correct_usage(self):
        bucket_metadata = json.dumps({"name": "bucket-test"})
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=len(bucket_metadata),
            data=bucket_metadata,
            content_type="application/json",
            method="POST",
        )

        bucket, _ = gcs.bucket.Bucket.init(Request(environ), None)
        bucket = bucket.metadata
        data = json.dumps({"name": "a"})
        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={"name": "a"},
            content_length=len(data),
            data=data,
            content_type="application/json",
            method="POST",
        )
        _ = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)

        data = json.dumps({"name": "a"})
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=len(data),
            data=data,
            content_type="application/json",
            method="POST",
        )
        _ = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)

        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={"name": "a"},
            content_type="application/json",
            method="POST",
        )
        _ = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)

        data = json.dumps({"name": None})
        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={"name": "b"},
            content_length=len(data),
            data=data,
            content_type="application/json",
            method="POST",
        )
        _ = gcs.upload.Upload.init_resumable_rest(Request(environ), bucket)

    def test_resumable_rest_with_none_hashes(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        data = json.dumps(
            {
                # Empty payload checksums
                "crc32c": None,
                "md5Hash": None,
                "name": "test-object-name",
            }
        )
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=len(data),
            data=data,
            content_type="application/json",
            method="POST",
        )
        upload = gcs.upload.Upload.init_resumable_rest(
            Request(environ), bucket.metadata
        )
        self.assertIn(
            "http://localhost:8080/upload/storage/v1/b/bucket-name/o", upload.location
        )

    def test_resumable_rest(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        data = json.dumps(
            {
                # Empty payload checksums
                "crc32c": "AAAAAA==",
                "md5Hash": "1B2M2Y8AsgTpgAmY7PhCfg==",
                "name": "test-object-name",
            }
        )
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=len(data),
            data=data,
            content_type="application/json",
            method="POST",
            query_string={"ifGenerationMatch": 42, "ifMetagenerationMatch": 43},
        )
        upload = gcs.upload.Upload.init_resumable_rest(
            Request(environ), bucket.metadata
        )
        self.assertIn(
            "http://localhost:8080/upload/storage/v1/b/bucket-name/o", upload.location
        )
        self.assertIn("uploadType=resumable", upload.location)
        self.assertIn("upload_id=" + upload.upload_id, upload.location)
        self.assertEqual(upload.metadata.name, "test-object-name")
        self.assertEqual(upload.metadata.checksums.crc32c, 0)
        self.assertEqual(
            upload.metadata.checksums.md5_hash,
            base64.b64decode("1B2M2Y8AsgTpgAmY7PhCfg=="),
        )
        self.assertTrue(hasattr(upload, "preconditions"))
        self.assertEqual(len(upload.preconditions), 2)

        app = flask.Flask(__name__)
        with app.test_request_context():
            status = upload.resumable_status_rest()
            self.assertEqual(status.status_code, 308)
            # Simulate a previous chunk upload
            upload.media = "The quick brown fox jumps over the lazy dog"
            status = upload.resumable_status_rest()
            self.assertEqual(status.status_code, 308)
            self.assertIn("Range", status.headers)
            self.assertEqual("bytes=0-42", status.headers.get("Range", None))
            # Simulate a chunk upload that requests 200 status code instead of 308
            upload.media = "How vexingly quick daft zebras jump"
            status = upload.resumable_status_rest(override_308=True)
            self.assertEqual(status.status_code, 200)
            self.assertIn("X-Http-Status-Code-Override", status.headers)

    def test_init_object_write_grpc_non_resumable(self):
        line = b"The quick brown fox jumps over the lazy dog\n"
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)

        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=2 * len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=True,
        )
        context = self.mock_context()
        db = unittest.mock.Mock()
        db.get_bucket = unittest.mock.MagicMock(return_value=bucket)
        upload, is_resumable = gcs.upload.Upload.init_write_object_grpc(
            db, [r1, r2, r3], context
        )
        self.assertIsNotNone(upload)
        self.assertFalse(is_resumable)
        self.assertEqual(upload.media, b"".join(3 * [line]))
        self.assertEqual(upload.metadata.name, "object")
        self.assertEqual(upload.metadata.bucket, "projects/_/buckets/bucket-name")
        db.get_bucket.assert_called_once_with("projects/_/buckets/bucket-name", context)

    def test_init_object_write_grpc_checksums(self):
        media = b"The quick brown fox jumps over the lazy dog"
        proto_crc32c = crc32c.crc32c(media)
        proto_md5_hash = hashlib.md5(media).digest()

        TEST_CASES = {
            "both": {
                "checksums": storage_pb2.ObjectChecksums(
                    crc32c=proto_crc32c, md5_hash=proto_md5_hash
                ),
                "expected": {
                    "x_emulator_crc32c": testbench.common.rest_crc32c_from_proto(
                        proto_crc32c
                    ),
                    "x_emulator_md5": testbench.common.rest_md5_from_proto(
                        proto_md5_hash
                    ),
                },
            },
            "only md5": {
                "checksums": storage_pb2.ObjectChecksums(md5_hash=proto_md5_hash),
                "expected": {
                    "x_emulator_md5": testbench.common.rest_md5_from_proto(
                        proto_md5_hash
                    ),
                    "x_emulator_no_crc32c": "true",
                },
            },
            "only crc32c": {
                "checksums": storage_pb2.ObjectChecksums(crc32c=proto_crc32c),
                "expected": {
                    "x_emulator_crc32c": testbench.common.rest_crc32c_from_proto(
                        proto_crc32c
                    ),
                    "x_emulator_no_md5": "true",
                },
            },
        }
        for name, test in TEST_CASES.items():
            request = testbench.common.FakeRequest(
                args={}, data=json.dumps({"name": "bucket-name"})
            )
            bucket, _ = gcs.bucket.Bucket.init(request, None)
            spec = storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            )
            request = storage_pb2.WriteObjectRequest(
                write_object_spec=spec,
                write_offset=0,
                object_checksums=test["checksums"],
                finish_write=True,
            )

            context = self.mock_context()
            db = unittest.mock.Mock()
            db.get_bucket = unittest.mock.MagicMock(return_value=bucket)
            upload, is_resumable = gcs.upload.Upload.init_write_object_grpc(
                db, [request], context
            )
            # Verify the annotations inserted by the testbench.
            annotations = upload.metadata.metadata
            expected = test["expected"]
            self.maxDiff = None
            self.assertEqual(
                annotations,
                {**annotations, **expected},
                msg="Testing with %s checksums" % name,
            )

    def test_init_resumable_grpc(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        spec = storage_pb2.WriteObjectSpec(
            resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            predefined_acl="projectPrivate",
            if_generation_not_match=1,
            if_metageneration_match=2,
            if_metageneration_not_match=3,
        )
        request = storage_pb2.StartResumableWriteRequest(write_object_spec=spec)
        upload = gcs.upload.Upload.init_resumable_grpc(
            request, bucket.metadata, self.mock_context()
        )
        # Verify the annotations inserted by the testbench.
        annotations = upload.metadata.metadata
        self.assertGreaterEqual(
            set(["x_emulator_upload", "x_emulator_no_crc32c", "x_emulator_no_md5"]),
            set(annotations.keys()),
        )
        # Clear any annotations created by the testbench.
        upload.metadata.metadata.clear()
        self.assertEqual(
            upload.metadata,
            storage_pb2.Object(name="object", bucket="projects/_/buckets/bucket-name"),
        )
        predefined_acl = testbench.acl.extract_predefined_acl(upload.request, False, "")
        self.assertEqual(predefined_acl, "projectPrivate")
        self.assertTrue(hasattr(upload, "preconditions"))
        self.assertEqual(len(upload.preconditions), 3)

    def test_init_object_write_grpc_resumable(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = storage_pb2.StartResumableWriteRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"}
            )
        )
        context = self.mock_context()
        upload = gcs.upload.Upload.init_resumable_grpc(
            request, bucket.metadata, context
        )

        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.WriteObjectRequest(
            upload_id=upload.upload_id,
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=2 * len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        context = self.mock_context()
        db = unittest.mock.Mock()
        db.get_bucket = unittest.mock.MagicMock(return_value=bucket)
        db.get_upload = unittest.mock.MagicMock(return_value=upload)
        upload, is_resumable = gcs.upload.Upload.init_write_object_grpc(
            db, [r1, r2, r3], context
        )
        self.assertIsNotNone(upload)
        self.assertFalse(upload.complete)
        self.assertTrue(is_resumable)
        self.assertEqual(upload.media, b"".join(3 * [line]))
        self.assertEqual(upload.metadata.name, "object")
        self.assertEqual(upload.metadata.bucket, "projects/_/buckets/bucket-name")

        r4 = storage_pb2.WriteObjectRequest(
            upload_id=upload.upload_id,
            write_offset=3 * len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=True,
        )
        upload, is_resumable = gcs.upload.Upload.init_write_object_grpc(
            db, [r4], context
        )
        self.assertIsNotNone(upload)
        self.assertTrue(upload.complete)
        self.assertTrue(is_resumable)
        self.assertEqual(upload.media, b"".join(4 * [line]))
        self.assertEqual(upload.metadata.name, "object")
        self.assertEqual(upload.metadata.bucket, "projects/_/buckets/bucket-name")

    def test_init_object_write_grpc_cannot_resume_completed_upload(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = storage_pb2.StartResumableWriteRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"}
            )
        )
        context = self.mock_context()
        upload = gcs.upload.Upload.init_resumable_grpc(
            request, bucket.metadata, context
        )

        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.WriteObjectRequest(
            upload_id=upload.upload_id,
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        db.get_bucket = unittest.mock.MagicMock(return_value=bucket)
        db.get_upload = unittest.mock.MagicMock(return_value=upload)

        context = self.mock_context()
        upload, _ = gcs.upload.Upload.init_write_object_grpc(db, [r1], context)
        self.assertIsNotNone(upload)
        self.assertTrue(upload.complete)

        context = self.mock_context()
        context.abort = unittest.mock.MagicMock()
        upload, _ = gcs.upload.Upload.init_write_object_grpc(db, [r1], context)
        self.assertIsNone(upload)
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_init_object_write_grpc_missing_first_message(self):
        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.WriteObjectRequest(
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        context = self.mock_context()
        upload, _ = gcs.upload.Upload.init_write_object_grpc(db, [r1], context)
        self.assertIsNone(upload)
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_init_object_write_grpc_missing_checksum_at_invalid_place(self):
        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            object_checksums=storage_pb2.ObjectChecksums(
                crc32c=crc32c.crc32c(b"".join(3 * [line]))
            ),
            finish_write=False,
        )
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=2 * len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        context = self.mock_context()
        upload, _ = gcs.upload.Upload.init_write_object_grpc(db, [r1, r2, r3], context)
        self.assertIsNone(upload)
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_init_object_write_grpc_missing_checksum_duplicated(self):
        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            object_checksums=storage_pb2.ObjectChecksums(
                crc32c=crc32c.crc32c(b"".join(3 * [line]))
            ),
            finish_write=False,
        )
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=2 * len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            object_checksums=storage_pb2.ObjectChecksums(
                crc32c=crc32c.crc32c(b"".join(3 * [line]))
            ),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        context = self.mock_context()
        upload, _ = gcs.upload.Upload.init_write_object_grpc(db, [r1, r2, r3], context)
        self.assertIsNone(upload)
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_init_object_write_grpc_invalid_checksum(self):
        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(2 * line)
            ),
            object_checksums=storage_pb2.ObjectChecksums(
                crc32c=crc32c.crc32c(b"".join(3 * [line]))
            ),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        context = self.mock_context()
        upload, _ = gcs.upload.Upload.init_write_object_grpc(db, [r1], context)
        self.assertIsNone(upload)
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_init_object_write_grpc_empty(self):
        db = unittest.mock.Mock()
        context = self.mock_context()
        upload, _ = gcs.upload.Upload.init_write_object_grpc(db, [], context)
        self.assertIsNone(upload)
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_init_object_write_grpc_final_message_empty_data(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = storage_pb2.StartResumableWriteRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"}
            )
        )
        context = self.mock_context()
        upload = gcs.upload.Upload.init_resumable_grpc(
            request, bucket.metadata, context
        )

        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.WriteObjectRequest(
            upload_id=upload.upload_id,
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=len(line),
            finish_write=True,
        )
        context = self.mock_context()
        db = unittest.mock.Mock()
        db.get_bucket = unittest.mock.MagicMock(return_value=bucket)
        db.get_upload = unittest.mock.MagicMock(return_value=upload)
        upload, is_resumable = gcs.upload.Upload.init_write_object_grpc(
            db, [r1, r2], context
        )
        self.assertIsNotNone(upload)
        self.assertTrue(upload.complete)
        self.assertTrue(is_resumable)
        self.assertEqual(upload.media, b"".join([line]))
        self.assertEqual(upload.metadata.name, "object")
        self.assertEqual(upload.metadata.bucket, "projects/_/buckets/bucket-name")

    def test_init_object_write_grpc_message_invalid_data(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = storage_pb2.StartResumableWriteRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"}
            )
        )
        context = self.mock_context()
        upload = gcs.upload.Upload.init_resumable_grpc(
            request, bucket.metadata, context
        )

        r1 = storage_pb2.WriteObjectRequest(
            upload_id=upload.upload_id,
            write_offset=0,
            finish_write=False,
        )

        context = self.mock_context()
        db = unittest.mock.Mock()
        db.get_bucket = unittest.mock.MagicMock(return_value=bucket)
        db.get_upload = unittest.mock.MagicMock(return_value=upload)
        upload, _ = gcs.upload.Upload.init_write_object_grpc(db, [r1], context)
        self.assertIsNone(upload)
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_process_bidi_write_grpc_resumable(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = storage_pb2.StartResumableWriteRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"}
            )
        )
        context = self.mock_context()
        upload = gcs.upload.Upload.init_resumable_grpc(
            request, bucket.metadata, context
        )

        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.BidiWriteObjectRequest(
            upload_id=upload.upload_id,
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=True,
        )
        r2 = copy.deepcopy(r1)
        db = unittest.mock.Mock()
        db.get_bucket = unittest.mock.MagicMock(return_value=bucket)
        db.get_upload = unittest.mock.MagicMock(return_value=upload)

        context = self.mock_context()
        streamer = gcs.upload.Upload.process_bidi_write_object_grpc(db, [r1], context)
        responses = list(streamer)
        blob = responses[0].resource
        self.assertEqual(blob.name, "object")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

        # Test resuming an already finalized object will result with
        # a response containing the finalized object's metadata.
        context = self.mock_context()
        streamer = gcs.upload.Upload.process_bidi_write_object_grpc(db, [r2], context)
        responses = list(streamer)
        blob = responses[0].resource
        self.assertEqual(blob.name, "object")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_process_bidi_write_grpc_missing_first_message(self):
        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.BidiWriteObjectRequest(
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        # The code depends on `context.abort()` raising an exception.
        context = self.mock_context()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            list(gcs.upload.Upload.process_bidi_write_object_grpc(db, [r1], context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_process_bidi_write_grpc_missing_finish_write(self):
        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.BidiWriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        db = unittest.mock.Mock()
        # The code depends on `context.abort()` raising an exception.
        context = self.mock_context()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            list(gcs.upload.Upload.process_bidi_write_object_grpc(db, [r1], context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_process_bidi_write_grpc_missing_checksum_at_invalid_place(self):
        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.BidiWriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r2 = storage_pb2.BidiWriteObjectRequest(
            write_offset=len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            object_checksums=storage_pb2.ObjectChecksums(
                crc32c=crc32c.crc32c(b"".join(3 * [line]))
            ),
            finish_write=False,
        )
        r3 = storage_pb2.BidiWriteObjectRequest(
            write_offset=2 * len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        # The code depends on `context.abort()` raising an exception.
        context = self.mock_context()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            list(
                gcs.upload.Upload.process_bidi_write_object_grpc(
                    db, [r1, r2, r3], context
                )
            )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_process_bidi_write_grpc_checksum_duplicated(self):
        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.BidiWriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            object_checksums=storage_pb2.ObjectChecksums(
                crc32c=crc32c.crc32c(b"".join(3 * [line]))
            ),
            finish_write=False,
        )
        r2 = storage_pb2.BidiWriteObjectRequest(
            write_offset=len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r3 = storage_pb2.BidiWriteObjectRequest(
            write_offset=2 * len(line),
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            object_checksums=storage_pb2.ObjectChecksums(
                crc32c=crc32c.crc32c(b"".join(3 * [line]))
            ),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        # The code depends on `context.abort()` raising an exception.
        context = self.mock_context()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            list(
                gcs.upload.Upload.process_bidi_write_object_grpc(
                    db, [r1, r2, r3], context
                )
            )
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_process_bidi_write_grpc_invalid_checksum(self):
        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.BidiWriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            ),
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(2 * line)
            ),
            object_checksums=storage_pb2.ObjectChecksums(
                crc32c=crc32c.crc32c(b"".join(3 * [line]))
            ),
            finish_write=True,
        )
        db = unittest.mock.Mock()
        # The code depends on `context.abort()` raising an exception.
        context = self.mock_context()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            list(gcs.upload.Upload.process_bidi_write_object_grpc(db, [r1], context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.FAILED_PRECONDITION, unittest.mock.ANY
        )

    def test_process_bidi_write_grpc_checksums(self):
        media = b"The quick brown fox jumps over the lazy dog"
        proto_crc32c = crc32c.crc32c(media)
        proto_md5_hash = hashlib.md5(media).digest()

        TEST_CASES = {
            "both": {
                "checksums": storage_pb2.ObjectChecksums(
                    crc32c=proto_crc32c, md5_hash=proto_md5_hash
                ),
                "expected": {
                    "x_emulator_crc32c": testbench.common.rest_crc32c_from_proto(
                        proto_crc32c
                    ),
                    "x_emulator_md5": testbench.common.rest_md5_from_proto(
                        proto_md5_hash
                    ),
                },
            },
            "only md5": {
                "checksums": storage_pb2.ObjectChecksums(md5_hash=proto_md5_hash),
                "expected": {
                    "x_emulator_md5": testbench.common.rest_md5_from_proto(
                        proto_md5_hash
                    ),
                    "x_emulator_no_crc32c": "true",
                },
            },
            "only crc32c": {
                "checksums": storage_pb2.ObjectChecksums(crc32c=proto_crc32c),
                "expected": {
                    "x_emulator_crc32c": testbench.common.rest_crc32c_from_proto(
                        proto_crc32c
                    ),
                    "x_emulator_no_md5": "true",
                },
            },
        }
        for name, test in TEST_CASES.items():
            request = testbench.common.FakeRequest(
                args={}, data=json.dumps({"name": "bucket-name"})
            )
            bucket, _ = gcs.bucket.Bucket.init(request, None)
            spec = storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            )
            request = storage_pb2.BidiWriteObjectRequest(
                write_object_spec=spec,
                write_offset=0,
                object_checksums=test["checksums"],
                finish_write=True,
            )

            context = self.mock_context()
            db = unittest.mock.Mock()
            db.get_bucket = unittest.mock.MagicMock(return_value=bucket)
            responses = list(
                gcs.upload.Upload.process_bidi_write_object_grpc(db, [request], context)
            )
            # Verify the annotations inserted by the testbench.
            annotations = responses[0].resource.metadata
            expected = test["expected"]
            self.maxDiff = None
            self.assertEqual(
                annotations,
                {**annotations, **expected},
                msg="Testing with %s checksums" % name,
            )

    def test_process_bidi_write_grpc_empty(self):
        db = unittest.mock.Mock()
        # The code depends on `context.abort()` raising an exception.
        context = self.mock_context()
        context.abort.side_effect = grpc.RpcError()
        with self.assertRaises(grpc.RpcError):
            list(gcs.upload.Upload.process_bidi_write_object_grpc(db, [], context))
        context.abort.assert_called_once_with(
            grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
        )

    def test_process_bidi_write_grpc_final_message_empty_data(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        request = storage_pb2.StartResumableWriteRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"}
            )
        )
        context = self.mock_context()
        upload = gcs.upload.Upload.init_resumable_grpc(
            request, bucket.metadata, context
        )

        line = b"The quick brown fox jumps over the lazy dog"
        r1 = storage_pb2.BidiWriteObjectRequest(
            upload_id=upload.upload_id,
            write_offset=0,
            checksummed_data=storage_pb2.ChecksummedData(
                content=line, crc32c=crc32c.crc32c(line)
            ),
            finish_write=False,
        )
        r2 = storage_pb2.BidiWriteObjectRequest(
            write_offset=len(line),
            finish_write=True,
        )
        context = self.mock_context()
        db = unittest.mock.Mock()
        db.get_bucket = unittest.mock.MagicMock(return_value=bucket)
        db.get_upload = unittest.mock.MagicMock(return_value=upload)
        responses = list(
            gcs.upload.Upload.process_bidi_write_object_grpc(db, [r1, r2], context)
        )
        blob = responses[0].resource
        self.assertEqual(blob.name, "object")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")
        self.assertTrue(upload.complete)


if __name__ == "__main__":
    unittest.main()
