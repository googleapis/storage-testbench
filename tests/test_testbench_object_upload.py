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

"""Unit test for Object Upload operations in the testbench."""

import json
import os
import re
import unittest
import platform

from testbench import rest_server
from tests.format_multipart_upload import format_multipart_upload


UPLOAD_QUANTUM = 256 * 1024


class TestTestbenchObjectUpload(unittest.TestCase):
    def setUp(self):
        rest_server.db.clear()
        self.client = rest_server.server.test_client()
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

    def test_upload_simple(self):
        payload = "How vexingly quick daft zebras jump!"
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"name": "zebra", "uploadType": "media"},
            content_type="text/plain",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertEqual(insert_rest.get("kind"), "storage#object")
        self.assertIn("bucket", insert_rest)
        self.assertIn("name", insert_rest)
        self.assertIn("generation", insert_rest)

        response = self.client.get("/storage/v1/b/bucket-name/o/zebra")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(insert_rest, get_rest)

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), payload)

    def test_upload_multipart(self):
        media = "How vexingly quick daft zebras jump!"
        boundary, payload = format_multipart_upload({}, media)
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "multipart", "name": "zebra"},
            content_type="multipart/related; boundary=" + boundary,
            data=payload,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertEqual(insert_rest.get("kind"), "storage#object")
        self.assertIn("bucket", insert_rest)
        self.assertIn("name", insert_rest)
        self.assertIn("generation", insert_rest)

        response = self.client.get("/storage/v1/b/bucket-name/o/zebra")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(insert_rest, get_rest)

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), media)

    @staticmethod
    def _create_valid_chunk():
        line = "How vexingly quick daft zebras jump!"
        pad = (255 - len(line)) * " "
        line = line + pad + "\n"
        return 1024 * line

    def test_upload_resumable_upload_crud(self):
        """Verify we can create, update, query, and delete resumable uploads."""
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "resumable", "name": "zebra"},
            content_type="application/json",
            data=json.dumps({"name": "zebra", "metadata": {"key0": "label0"}}),
        )
        self.assertEqual(response.status_code, 200)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        upload_id = match.group(1)

        # Upload at least some data before querying
        chunk = self._create_valid_chunk()
        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={"content-range": "bytes 0-{last:d}/*".format(last=len(chunk) - 1)},
            data=chunk,
        )

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={"content-range": "bytes */*"},
        )
        self.assertEqual(response.status_code, 308, msg=response.data)
        self.assertIn("range", response.headers)

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={"content-range": "bytes */%d" % 2 * UPLOAD_QUANTUM},
        )
        self.assertEqual(response.status_code, 308)
        self.assertIn("range", response.headers)

        # Upload another chunk using a POST request with upload_id
        chunk = self._create_valid_chunk()
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes {beg:d}-{last:d}/*".format(
                    beg=2 * UPLOAD_QUANTUM - 1, last=3 * UPLOAD_QUANTUM - 1
                )
            },
            data=chunk,
        )
        self.assertEqual(response.status_code, 308)
        self.assertIn("range", response.headers)

        # Test 200 overrides 308 with request header X-Guploader-No-308
        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "X-Guploader-No-308": "yes",
            },
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.delete(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
        )
        # Deleting uploads is weird, it always returns 499.
        self.assertEqual(response.status_code, 499)

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={"content-range": "bytes */*"},
        )
        self.assertEqual(response.status_code, 404)

    def test_upload_resumable(self):
        media = "How vexingly quick daft zebras jump!"
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "resumable", "name": "zebra"},
            content_type="application/json",
            data=json.dumps({"name": "zebra", "metadata": {"key0": "label0"}}),
        )
        self.assertEqual(response.status_code, 200)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        upload_id = match.group(1)

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            data=media,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertIn("metadata", insert_rest)
        insert_metadata = insert_rest.get("metadata")
        self.assertEqual(insert_metadata, {**insert_metadata, **{"key0": "label0"}})

        response = self.client.get("/storage/v1/b/bucket-name/o/zebra")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(insert_rest, get_rest)

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), media)

    def test_upload_resumable_x_upload_content_length(self):
        chunk = self._create_valid_chunk()
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "resumable", "name": "zebra"},
            content_type="application/json",
            headers={"x-upload-content-length": "%d" % (2 * len(chunk))},
            data=json.dumps({"name": "zebra", "metadata": {"key0": "label0"}}),
        )
        self.assertEqual(response.status_code, 200)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        upload_id = match.group(1)

        # Upload in chunks, but there is not need to specify the ending byte because
        #  it was set via the x-upload-content-length header.
        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes 0-{last:d}/*".format(last=len(chunk) - 1),
                "x-upload-content-length": "%d" % (2 * len(chunk)),
            },
            data=chunk,
        )
        self.assertEqual(response.status_code, 308, msg=response.data)

        chunk = self._create_valid_chunk()
        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes {last:d}-*/*".format(last=len(chunk) - 1),
            },
            data=chunk,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertIn("metadata", insert_rest)
        insert_metadata = insert_rest.get("metadata")
        self.assertEqual(insert_metadata, {**insert_metadata, **{"key0": "label0"}})

        response = self.client.get("/storage/v1/b/bucket-name/o/zebra")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(insert_rest, get_rest)

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), 2 * chunk)

    def test_upload_resumable_x_upload_content_length_mismatch(self):
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "resumable", "name": "zebra"},
            # Send the x-upload-content-length, but set it to the wrong value,
            # this should result in an error, checked below
            headers={"x-upload-content-length": "1234"},
            content_type="application/json",
            data=json.dumps({"name": "zebra", "metadata": {"key0": "label0"}}),
        )
        self.assertEqual(response.status_code, 200)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        upload_id = match.group(1)

        chunk = self._create_valid_chunk()
        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                # write a single chunk that is the full contents, but...
                "content-range": "bytes 0-{last:d}/{len:d}".format(
                    last=len(chunk) - 1, len=len(chunk)
                )
            },
            data=chunk,
        )
        self.assertEqual(response.status_code, 400, msg=response.data)

    def test_upload_resumable_unknown_location(self):
        media = ""
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "resumable", "name": "empty"},
            content_type="application/json",
            data=json.dumps({"name": "empty", "metadata": {"key0": "label0"}}),
        )
        self.assertEqual(response.status_code, 200)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        upload_id = match.group(1)

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes */0",
            },
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertIn("metadata", insert_rest)
        insert_metadata = insert_rest.get("metadata")
        self.assertEqual(insert_metadata, {**insert_metadata, **{"key0": "label0"}})

        response = self.client.get("/storage/v1/b/bucket-name/o/empty")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(insert_rest, get_rest)

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/empty", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), "")

    def test_upload_resumable_multiple_chunks(self):
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "resumable", "name": "zebra"},
            content_type="application/json",
            data=json.dumps({"name": "zebra", "metadata": {"key0": "label0"}}),
        )
        self.assertEqual(response.status_code, 200)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        upload_id = match.group(1)

        chunk = self._create_valid_chunk()
        self.assertEqual(len(chunk), UPLOAD_QUANTUM)

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes 0-{len:d}/*".format(len=UPLOAD_QUANTUM - 1)
            },
            data=chunk,
        )
        self.assertEqual(response.status_code, 308, msg=response.data)
        self.assertIn("range", response.headers)
        self.assertEqual(
            response.headers.get("range"), "bytes=0-%d" % (UPLOAD_QUANTUM - 1)
        )

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes {beg:d}-{end:d}/*".format(
                    beg=UPLOAD_QUANTUM, end=2 * UPLOAD_QUANTUM - 1
                )
            },
            data=chunk,
        )
        self.assertEqual(response.status_code, 308, msg=response.data)
        self.assertIn("range", response.headers)
        self.assertEqual(
            response.headers.get("range"), "bytes=0-%d" % (2 * UPLOAD_QUANTUM - 1)
        )

        # Finalize upload with an empty chunk
        self.assertEqual(len(chunk), UPLOAD_QUANTUM)
        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes 0-{last:d}/{len:d}".format(
                    last=2 * UPLOAD_QUANTUM - 1, len=2 * UPLOAD_QUANTUM
                )
            },
            data="",
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), 2 * chunk)

    def test_upload_resumable_query_completed(self):
        media = "How vexingly quick daft zebras jump!"
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "resumable", "name": "zebra"},
            content_type="application/json",
            data=json.dumps({"name": "zebra", "metadata": {"key0": "label0"}}),
        )
        self.assertEqual(response.status_code, 200)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        upload_id = match.group(1)

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes 0-{last:d}/{len:d}".format(
                    last=len(media) - 1, len=len(media)
                )
            },
            data=media,
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)

        # Querying the status of a resumable upload after the upload completes
        # should return the finalized object metadata.
        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={"content-range": "bytes */*"},
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        query_rest = json.loads(response.data)
        # Drop the fields excluded by the noAcl projection
        query_rest.pop("acl")
        query_rest.pop("owner")
        self.assertEqual(insert_rest, query_rest)

    def test_upload_validate_upload_type(self):
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"name": "zebra"},
            content_type="text/plain",
            data="",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"name": "zebra", "uploadType": "invalid"},
            content_type="text/plain",
            data="",
        )
        self.assertEqual(response.status_code, 400)

    def test_upload_validate_upload_id(self):
        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"missing_upload_id": "test-only-unused"},
            data="",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": "test-only-invalid"},
            data="",
        )
        self.assertEqual(response.status_code, 404)

    def get_upload_id(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertIn("location", response.headers)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        return match.group(1)

    def test_upload_pre_conditions_success(self):
        FIXED_QUERY_STRING = {"uploadType": "resumable", "name": "zebra"}
        TEST_CASES = {
            "ifGenerationMatch": lambda object: {
                "ifGenerationMatch": object["generation"]
            },
            "ifMetagenerationMatch": lambda object: {
                "ifMetagenerationMatch": object["metageneration"]
            },
        }

        for name, action in TEST_CASES.items():
            # First create an object using the a simple upload, then try to
            # overwrite it. Using a precondition that should succeed.
            media = "How vexingly quick daft zebras jump!"
            response = self.client.post(
                "/upload/storage/v1/b/bucket-name/o",
                query_string={"uploadType": "media", "name": "zebra"},
                content_type="text/plain",
                data=media.encode("utf-8"),
            )
            self.assertEqual(response.status_code, 200)
            insert_rest = json.loads(response.data)

            media = "The quick brown fox jumps over the lazy dog"
            response = self.client.post(
                "/upload/storage/v1/b/bucket-name/o",
                query_string={**FIXED_QUERY_STRING, **action(insert_rest)},
                content_type="application/json",
                data=json.dumps({"name": "zebra"}),
            )
            upload_id = self.get_upload_id(response)

            response = self.client.put(
                "/upload/storage/v1/b/bucket-name/o",
                query_string={"upload_id": upload_id},
                data=media,
            )
            self.assertEqual(response.status_code, 200, msg=name)
            self.assertTrue(
                response.headers.get("content-type").startswith("application/json")
            )
            upload_rest = json.loads(response.data)

            # TODO(#453) - restore this test for Windows
            if platform.system().lower() != "windows":
                self.assertNotEqual(
                    upload_rest.get("generation"), insert_rest["generation"]
                )

    def test_upload_pre_conditions_failure(self):
        FIXED_QUERY_STRING = {"uploadType": "resumable", "name": "zebra"}
        TEST_CASES = {
            "ifGenerationMatch": lambda _: {"ifGenerationMatch": -1},
            "ifMetagenerationMatch": lambda _: {"ifMetagenerationMatch": -1},
        }

        for name, action in TEST_CASES.items():
            # First create an object using the a simple upload, then try to
            # overwrite it. Using a precondition that should fail.
            media = "How vexingly quick daft zebras jump!"
            response = self.client.post(
                "/upload/storage/v1/b/bucket-name/o",
                query_string={"uploadType": "media", "name": "zebra"},
                content_type="text/plain",
                data=media.encode("utf-8"),
            )
            self.assertEqual(response.status_code, 200)
            insert_rest = json.loads(response.data)
            self.assertIn("generation", insert_rest)

            media = "The quick brown fox jumps over the lazy dog"
            response = self.client.post(
                "/upload/storage/v1/b/bucket-name/o",
                query_string={**FIXED_QUERY_STRING, **action(insert_rest)},
                content_type="application/json",
                data=json.dumps({"name": "zebra"}),
            )
            upload_id = self.get_upload_id(response)

            response = self.client.put(
                "/upload/storage/v1/b/bucket-name/o",
                query_string={"upload_id": upload_id},
                data=media,
            )
            self.assertEqual(response.status_code, 412, msg=name)


if __name__ == "__main__":
    unittest.main()
