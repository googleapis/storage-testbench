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

import crc32c
import base64
import hashlib
import flask
import json
import unittest

from google.storage.v2 import storage_pb2
from google.protobuf import json_format

from werkzeug.test import create_environ
from werkzeug.wrappers import Request

import gcs
import testbench


class TestHolder(unittest.TestCase):
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
            upload = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)
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
            upload = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)
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
            _ = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)
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
            _ = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)
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
            _ = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)
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
            upload = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)
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
        upload = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)

        data = json.dumps({"name": "a"})
        environ = create_environ(
            base_url="http://localhost:8080",
            content_length=len(data),
            data=data,
            content_type="application/json",
            method="POST",
        )
        upload = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)

        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={"name": "a"},
            content_type="application/json",
            method="POST",
        )
        upload = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)

        data = json.dumps({"name": None})
        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={"name": "b"},
            content_length=len(data),
            data=data,
            content_type="application/json",
            method="POST",
        )
        upload = gcs.holder.DataHolder.init_resumable_rest(Request(environ), bucket)

    def test_init_resumable_grpc(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket-name"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        spec = storage_pb2.WriteObjectSpec(
            resource={"name": "object", "bucket": "projects/_/buckets/bucket-name"},
            predefined_acl=storage_pb2.PredefinedObjectAcl.OBJECT_ACL_PROJECT_PRIVATE,
            if_generation_not_match=1,
            if_metageneration_match=2,
            if_metageneration_not_match=3,
        )
        request = storage_pb2.WriteObjectRequest(write_object_spec=spec, write_offset=0)
        upload = gcs.holder.DataHolder.init_resumable_grpc(request, bucket.metadata, "")
        # Verify the annotations inserted by the emulator.
        annotations = upload.metadata.metadata
        self.assertGreaterEqual(
            set(["x_emulator_upload", "x_emulator_no_crc32c", "x_emulator_no_md5"]),
            set(annotations.keys()),
        )
        # Clear any annotations created by the emulator
        upload.metadata.metadata.clear()
        self.assertEqual(
            upload.metadata,
            storage_pb2.Object(name="object", bucket="projects/_/buckets/bucket-name"),
        )
        predefined_acl = testbench.acl.extract_predefined_acl(upload.request, False, "")
        self.assertEqual(
            predefined_acl, storage_pb2.PredefinedObjectAcl.OBJECT_ACL_PROJECT_PRIVATE
        )
        match, not_match = testbench.generation.extract_precondition(
            upload.request, False, False, None
        )
        self.assertIsNone(match)
        self.assertEqual(not_match, 1)
        match, not_match = testbench.generation.extract_precondition(
            upload.request, True, False, None
        )
        self.assertEqual(match, 2)
        self.assertEqual(not_match, 3)

    def test_init_resumable_grpc_with_checksums(self):
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
            )
            upload = gcs.holder.DataHolder.init_resumable_grpc(
                request, bucket.metadata, ""
            )
            # Verify the annotations inserted by the emulator.
            annotations = upload.metadata.metadata
            expected = test["expected"]
            self.maxDiff = None
            self.assertEqual(
                annotations,
                {**annotations, **expected},
                msg="Testing with %s checksums" % name,
            )

    def test_resumable_rest(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket"})
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
        )
        upload = gcs.holder.DataHolder.init_resumable_rest(
            Request(environ), bucket.metadata
        )
        self.assertEqual(upload.metadata.name, "test-object-name")
        self.assertEqual(upload.metadata.checksums.crc32c, 0)
        self.assertEqual(
            upload.metadata.checksums.md5_hash,
            base64.b64decode("1B2M2Y8AsgTpgAmY7PhCfg=="),
        )

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

    def test_rewrite_rest(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        bucket = bucket.metadata
        data = json.dumps({"name": "a"})
        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={"maxBytesRewrittenPerCall": 512 * 1024},
        )
        upload = gcs.holder.DataHolder.init_rewrite_rest(
            Request(environ),
            "source-bucket",
            "source-object",
            "destination-bucket",
            "destination-object",
        )
        self.assertEqual(512 * 1024, upload.max_bytes_rewritten_per_call)


if __name__ == "__main__":
    unittest.main()
