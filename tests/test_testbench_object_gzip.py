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

"""Unit test for downloading gzip-ed objects."""

import gzip
import json
import os
import re
import unittest

from testbench import rest_server
from tests.format_multipart_upload import format_multipart_upload_bytes

UPLOAD_QUANTUM = 256 * 1024


class TestTestbenchObjectGzip(unittest.TestCase):
    def setUp(self):
        rest_server.db.clear()
        rest_server.server.config["PREFERRED_URL_SCHEME"] = "https"
        rest_server.server.config["SERVER_NAME"] = "storage.googleapis.com"
        rest_server.root.config["PREFERRED_URL_SCHEME"] = "https"
        rest_server.root.config["SERVER_NAME"] = "storage.googleapis.com"
        self.client = rest_server.server.test_client(allow_subdomain_redirects=True)
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

    def _insert_compressed_object(self, name):
        media = "How vexingly quick daft zebras jump!"
        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={
                "name": name,
                "uploadType": "media",
                "contentEncoding": "gzip",
            },
            content_type="application/octet-stream",
            data=gzip.compress(media.encode("utf-8")),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertEqual(insert_rest.get("kind"), "storage#object")
        self.assertEqual(insert_rest.get("contentEncoding", ""), "gzip")

        return media

    def test_download_gzip_data_simple_upload(self):
        media = self._insert_compressed_object("zebra")

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), media)
        self.assertEqual(
            response.headers.get("x-guploader-response-body-transformations", ""),
            "gunzipped",
        )

    def test_download_gzip_compressed(self):
        media = self._insert_compressed_object("zebra")

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra",
            query_string={"alt": "media"},
            headers={"Accept-Encoding": "gzip"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(gzip.decompress(response.data), media.encode("utf-8"))
        self.assertEqual(
            response.headers.get("x-guploader-response-body-transformations", ""), ""
        )

    def test_download_gzip_range_ignored(self):
        media = self._insert_compressed_object("zebra")

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra",
            query_string={"alt": "media"},
            headers={"Range": "4-8"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, media.encode("utf-8"))
        self.assertEqual(
            response.headers.get("x-guploader-response-body-transformations", ""),
            "gunzipped",
        )
        self.assertEqual(
            response.headers.get("content-range", ""),
            "bytes 0-%d/%d" % (len(media) - 1, len(media)),
        )

    def test_download_gzip_uncompressed_xml(self):
        media = self._insert_compressed_object("zebra")

        response = self.client.get(
            "/zebra", base_url="https://bucket-name.storage.googleapis.com"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, media.encode("utf-8"))
        self.assertEqual(
            response.headers.get("x-guploader-response-body-transformations", ""),
            "gunzipped",
        )
        self.assertEqual(
            response.headers.get("x-goog-stored-content-encoding", ""), "gzip"
        )

    def test_download_gzip_compressed_xml(self):
        media = self._insert_compressed_object("zebra")

        response = self.client.get(
            "/zebra",
            base_url="https://bucket-name.storage.googleapis.com",
            headers={"Accept-Encoding": "gzip"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(gzip.decompress(response.data), media.encode("utf-8"))
        self.assertEqual(
            response.headers.get("x-guploader-response-body-transformations", ""),
            "",
        )
        self.assertEqual(
            response.headers.get("x-goog-stored-content-encoding", ""), "gzip"
        )

    def test_download_of_multipart_upload(self):
        media = "How vexingly quick daft zebras jump!"
        boundary, payload = format_multipart_upload_bytes(
            {"contentEncoding": "gzip"}, gzip.compress(media.encode("utf-8"))
        )
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
        self.assertEqual(insert_rest.get("contentEncoding", ""), "gzip")
        self.assertEqual(
            response.headers.get("x-guploader-response-body-transformations", ""), ""
        )

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), media)
        self.assertEqual(
            response.headers.get("x-guploader-response-body-transformations", ""),
            "gunzipped",
        )

    def test_download_of_resumable_upload(self):
        media = "How vexingly quick daft zebras jump!"

        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "resumable", "name": "zebra"},
            content_type="application/json",
            data=json.dumps({"name": "zebra", "contentEncoding": "gzip"}),
        )
        self.assertEqual(response.status_code, 200)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        upload_id = match.group(1)

        finalized = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            data=gzip.compress(media.encode("utf-8")),
        )
        self.assertEqual(finalized.status_code, 200)
        self.assertTrue(
            finalized.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(finalized.data)
        self.assertIn("metadata", insert_rest)
        self.assertEqual(insert_rest.get("kind"), "storage#object")
        self.assertEqual(insert_rest.get("contentEncoding", ""), "gzip")

        response = self.client.get(
            "/download/storage/v1/b/bucket-name/o/zebra", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), media)
        self.assertEqual(
            response.headers.get("x-guploader-response-body-transformations", ""),
            "gunzipped",
        )


if __name__ == "__main__":
    unittest.main()
