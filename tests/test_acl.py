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


class TestACL(unittest.TestCase):
    def test_create_bucket_acl(self):
        actual = testbench.acl.create_bucket_acl(
            "bucket-name", "test-entity", "READER", context=None
        )
        self.assertEqual(actual.role, "READER")
        self.assertEqual(actual.entity, "test-entity")
        self.assertNotEqual(actual.id, "")
        self.assertNotEqual(actual.etag, "")

    def test_create_bucket_with_alt(self):
        actual = testbench.acl.create_bucket_acl(
            "bucket-name", "project-owners-project-id", "OWNER", context=None
        )
        self.assertEqual(actual.entity_alt, "project-owners-project-id")
        self.assertEqual(actual.role, "OWNER")
        self.assertEqual(
            actual.entity, testbench.acl.get_project_entity("owners", None)
        )
        self.assertNotEqual(actual.id, "")
        self.assertNotEqual(actual.etag, "")

    def test_create_default_object_acl(self):
        actual = testbench.acl.create_default_object_acl(
            "bucket-name", "test-entity", "READER", context=None
        )
        self.assertEqual(actual.role, "READER")
        self.assertEqual(actual.entity, "test-entity")
        self.assertNotEqual(actual.id, "")
        self.assertNotEqual(actual.etag, "")

    def test_create_object_acl(self):
        actual = testbench.acl.create_object_acl(
            "bucket-name", "object-name", 123, "test-entity", "OWNER", context=None
        )
        self.assertEqual(actual.role, "OWNER")
        self.assertEqual(actual.entity, "test-entity")
        self.assertNotEqual(actual.id, "")
        self.assertNotEqual(actual.etag, "")

    def test_create_object_with_alt(self):
        actual = testbench.acl.create_object_acl(
            "bucket-name",
            "object-name",
            123,
            "project-owners-project-id",
            "OWNER",
            context=None,
        )
        self.assertEqual(actual.entity_alt, "project-owners-project-id")
        self.assertEqual(actual.role, "OWNER")
        self.assertEqual(
            actual.entity, testbench.acl.get_project_entity("owners", None)
        )
        self.assertNotEqual(actual.id, "")
        self.assertNotEqual(actual.etag, "")

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

    def test_compute_predefined_object_acl(self):
        acls = testbench.acl.compute_predefined_object_acl(
            "bucket", "object", 123456789, "authenticatedRead", None
        )
        entities = [acl.entity for acl in acls]
        self.assertEqual(
            entities,
            [testbench.acl.get_object_entity("OWNER", None), "allAuthenticatedUsers"],
        )


if __name__ == "__main__":
    unittest.main()
