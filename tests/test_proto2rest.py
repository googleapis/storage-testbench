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
        }
        self.assertEqual(actual, {**actual, **expected})
        self.assertIn("etag", actual)


if __name__ == "__main__":
    unittest.main()
