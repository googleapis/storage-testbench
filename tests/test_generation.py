#!/usr/bin/env python3
#
# Copyright 2020 Google LLC
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

"""Unit tests for testbench.generation."""

import unittest
from google.storage.v2 import storage_pb2

import testbench.generation


class TestGeneration(unittest.TestCase):
    def test_extract_precondition(self):
        request = testbench.common.FakeRequest(
            args={
                "ifGenerationNotMatch": 1,
                "ifMetagenerationMatch": 2,
                "ifMetagenerationNotMatch": 3,
                "ifSourceGenerationMatch": 4,
                "ifSourceGenerationNotMatch": 5,
                "ifSourceMetagenerationMatch": 6,
                "ifSourceMetagenerationNotMatch": 7,
            }
        )
        match, not_match = testbench.generation.extract_precondition(
            request, False, False, None
        )
        self.assertIsNone(match)
        self.assertEqual(not_match, 1)
        match, not_match = testbench.generation.extract_precondition(
            request, True, False, None
        )
        self.assertEqual(match, 2)
        self.assertEqual(not_match, 3)
        match, not_match = testbench.generation.extract_precondition(
            request, False, True, None
        )
        self.assertEqual(match, 4)
        self.assertEqual(not_match, 5)
        match, not_match = testbench.generation.extract_precondition(
            request, True, True, None
        )
        self.assertEqual(match, 6)
        self.assertEqual(not_match, 7)

    def test_extract_generation(self):
        request = storage_pb2.ReadObjectRequest()
        generation = testbench.generation.extract_generation(request, False, "")
        self.assertEqual(generation, 0)

        request.generation = 1
        generation = testbench.generation.extract_generation(request, False, "")
        self.assertEqual(generation, 1)

        request = testbench.common.FakeRequest(args={})
        generation = testbench.generation.extract_generation(request, False, None)
        self.assertEqual(generation, 0)

        request.args["generation"] = 1
        request.args["sourceGeneration"] = 2
        generation = testbench.generation.extract_generation(request, False, None)
        self.assertEqual(generation, 1)
        generation = testbench.generation.extract_generation(request, True, None)
        self.assertEqual(generation, 2)

    def test_check_precondition_generation_matches_trivial(self):
        testbench.generation.check_precondition(
            1234, match=None, not_match=None, is_meta=None, context=None
        )

    def test_check_precondition_generation_matches_failure(self):
        cases = {
            True: "metageneration",
            False: "generation",
        }
        for is_meta, expected in cases.items():
            with self.assertRaises(testbench.error.RestException) as rest:
                testbench.generation.check_precondition(
                    1234, match=2345, not_match=None, is_meta=is_meta, context=None
                )
            self.assertEqual(rest.exception.code, 412)
            self.assertRegex(rest.exception.msg, r"\W" + expected)

    def test_check_precondition_generation_notmatches_failure(self):
        cases = {
            True: "metageneration",
            False: "generation",
        }
        for is_meta, expected in cases.items():
            with self.assertRaises(testbench.error.RestException) as rest:
                testbench.generation.check_precondition(
                    1234, match=None, not_match=1234, is_meta=is_meta, context=None
                )
            self.assertEqual(rest.exception.code, 304)
            self.assertRegex(rest.exception.msg, r"\W" + expected)


if __name__ == "__main__":
    unittest.main()
