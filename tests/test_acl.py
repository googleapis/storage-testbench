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

"""Unit test for testbench.acl"""

import unittest
import testbench

from google.cloud.storage_v1.proto import storage_pb2 as storage_pb2
from google.cloud.storage_v1.proto.storage_resources_pb2 import CommonEnums


class TestACL(unittest.TestCase):
    def test_get_canonical_entity(self):
        cases = {
            "allUsers": lambda x: self.assertEqual(x, "allUsers"),
            "allAuthenticatedUsers": lambda x: self.assertEqual(
                x, "allAuthenticatedUsers"
            ),
            "project-editors-": lambda x: self.assertTrue(
                x.startswith("project-editors-")
            ),
            "project-owners-": lambda x: self.assertTrue(
                x.startswith("project-owners-")
            ),
            "project-viewers-": lambda x: self.assertTrue(
                x.startswith("project-viewers-")
            ),
        }
        for input, checker in cases.items():
            checker(testbench.acl.get_canonical_entity(input))

    def test_extract_predefined_default_object_acl(self):
        request = testbench.common.FakeRequest(args={})
        predefined_default_object_acl = (
            testbench.acl.extract_predefined_default_object_acl(request, None)
        )
        self.assertEqual(predefined_default_object_acl, "")

        request.args["predefinedDefaultObjectAcl"] = "authenticatedRead"
        predefined_default_object_acl = (
            testbench.acl.extract_predefined_default_object_acl(request, None)
        )
        self.assertEqual(predefined_default_object_acl, "authenticatedRead")

    def test_extract_predefined_acl(self):
        request = testbench.common.FakeRequest(args={})
        predefined_acl = testbench.acl.extract_predefined_acl(request, False, None)
        self.assertEqual(predefined_acl, "")

        request.args["predefinedAcl"] = "authenticatedRead"
        predefined_acl = testbench.acl.extract_predefined_acl(request, False, None)
        self.assertEqual(predefined_acl, "authenticatedRead")

        request.args["destinationPredefinedAcl"] = "bucketOwnerFullControl"
        predefined_acl = testbench.acl.extract_predefined_acl(request, True, None)
        self.assertEqual(predefined_acl, "bucketOwnerFullControl")

    def test_compute_predefined_bucket_acl(self):
        cases = {
            "authenticatedRead": [
                testbench.acl.get_project_entity("owners", None),
                "allAuthenticatedUsers",
            ],
            "private": [testbench.acl.get_project_entity("owners", None)],
            "projectPrivate": [
                testbench.acl.get_project_entity("owners", None),
                testbench.acl.get_project_entity("editors", None),
                testbench.acl.get_project_entity("viewers", None),
            ],
            "publicRead": [
                testbench.acl.get_project_entity("owners", None),
                "allUsers",
            ],
            "publicReadWrite": [
                testbench.acl.get_project_entity("owners", None),
                "allUsers",
            ],
            "test-only-invalid": [],
        }
        for predefined, expected in cases.items():
            acls = testbench.acl.compute_predefined_bucket_acl(
                "bucket", predefined, None
            )
            entities = [acl.entity for acl in acls]
            self.assertListEqual(entities, expected, msg=predefined)

    def test_compute_predefined_default_object_acl(self):
        cases = {
            "authenticatedRead": [
                testbench.acl.get_object_entity("OWNER", None),
                "allAuthenticatedUsers",
            ],
            "bucketOwnerFullControl": [
                testbench.acl.get_object_entity("OWNER", None),
                testbench.acl.get_project_entity("owners", None),
            ],
            "bucketOwnerRead": [
                testbench.acl.get_object_entity("OWNER", None),
                testbench.acl.get_project_entity("owners", None),
            ],
            "private": [
                testbench.acl.get_object_entity("OWNER", None),
            ],
            "projectPrivate": [
                testbench.acl.get_object_entity("OWNER", None),
                testbench.acl.get_project_entity("owners", None),
                testbench.acl.get_project_entity("editors", None),
                testbench.acl.get_project_entity("viewers", None),
            ],
            "publicRead": [
                testbench.acl.get_object_entity("OWNER", None),
                "allUsers",
            ],
            "test-only-invalid": [],
        }
        for predefined, expected in cases.items():
            acls = testbench.acl.compute_predefined_default_object_acl(
                "bucket", predefined, None
            )
            entities = [acl.entity for acl in acls]
            self.assertEqual(entities, expected, msg=predefined)
            object_names = [acl.object for acl in acls]
            self.assertEqual(object_names, len(acls) * [""], msg=predefined)

    def test_compute_predefined_object_acl(self):
        acls = testbench.acl.compute_predefined_object_acl(
            "bucket", "object", 123456789, "authenticatedRead", None
        )
        entities = [acl.entity for acl in acls]
        self.assertEqual(
            entities,
            [testbench.acl.get_object_entity("OWNER", None), "allAuthenticatedUsers"],
        )

        object_names = [acl.object for acl in acls]
        self.assertEqual(object_names, 2 * ["object"])

        generations = [acl.generation for acl in acls]
        self.assertEqual(generations, 2 * [123456789])


if __name__ == "__main__":
    unittest.main()
