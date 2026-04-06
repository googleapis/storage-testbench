#!/usr/bin/env python3
# Copyright 2026 Google LLC
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

"""Test stall functionality for Storage Control API."""

import dataclasses
import os
import time
import unittest
import unittest.mock
from typing import Any, Callable, Optional

import grpc
from google.protobuf import empty_pb2

import testbench
from google.storage.control.v2 import storage_control_pb2


@dataclasses.dataclass
class ApiTestCase:
    name: str
    method_name: str
    request: Any
    setup_func: Optional[Callable[["TestStorageControlStall"], None]] = None
    verify_func: Optional[Callable[["TestStorageControlStall", Any], None]] = None


class TestStorageControlStall(unittest.TestCase):
    """Test cases for Storage Control API stall functionality."""

    def mock_context(self, metadata=None):
        """Create a mock context with optional metadata."""
        context = unittest.mock.Mock()
        if metadata is None:
            metadata = []
        context.invocation_metadata = unittest.mock.Mock(return_value=metadata)
        return context

    def setUp(self):
        self.original_env_bucket = os.environ.get(
            "GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME"
        )
        os.environ["GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME"] = "test-bucket"
        self.db = testbench.database.Database.init()
        self.servicer = testbench.grpc_server.StorageControlServicer(
            self.db, echo_metadata=False
        )

    def tearDown(self):
        if self.original_env_bucket is None:
            os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)
        else:
            os.environ[
                "GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME"
            ] = self.original_env_bucket

    def _create_folder(self, folder_id):
        request = storage_control_pb2.CreateFolderRequest(
            parent="projects/_/buckets/test-bucket", folder_id=folder_id
        )
        self.servicer.CreateFolder(request, self.mock_context())

    def test_no_stall_behaviors(self):
        """Table-driven test for no-stall behaviors across API methods."""
        test_cases = [
            ApiTestCase(
                name="create_folder_no_stall",
                method_name="CreateFolder",
                request=storage_control_pb2.CreateFolderRequest(
                    parent="projects/_/buckets/test-bucket", folder_id="create-no-stall"
                ),
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/folders/create-no-stall"
                ),
            ),
            ApiTestCase(
                name="delete_folder_no_stall",
                method_name="DeleteFolder",
                setup_func=lambda self: self._create_folder("delete-no-stall"),
                request=storage_control_pb2.DeleteFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/delete-no-stall"
                ),
                verify_func=lambda self, res: self.assertIsInstance(
                    res, empty_pb2.Empty
                ),
            ),
            ApiTestCase(
                name="get_folder_no_stall",
                method_name="GetFolder",
                setup_func=lambda self: self._create_folder("get-no-stall"),
                request=storage_control_pb2.GetFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/get-no-stall"
                ),
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/folders/get-no-stall"
                ),
            ),
            ApiTestCase(
                name="list_folders_no_stall",
                method_name="ListFolders",
                setup_func=lambda self: self._create_folder("list-no-stall"),
                request=storage_control_pb2.ListFoldersRequest(
                    parent="projects/_/buckets/test-bucket"
                ),
                verify_func=lambda self, res: self.assertGreaterEqual(
                    len(res.folders), 1
                ),
            ),
            ApiTestCase(
                name="rename_folder_no_stall",
                method_name="RenameFolder",
                setup_func=lambda self: self._create_folder("rename-src-no-stall"),
                request=storage_control_pb2.RenameFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/rename-src-no-stall",
                    destination_folder_id="projects/_/buckets/test-bucket/folders/rename-dst-no-stall",
                ),
                verify_func=lambda self, res: self.assertEqual(
                    res.name,
                    "projects/_/buckets/test-bucket/folders/rename-dst-no-stall",
                ),
            ),
            ApiTestCase(
                name="get_storage_layout_no_stall",
                method_name="GetStorageLayout",
                request=storage_control_pb2.GetStorageLayoutRequest(
                    name="projects/_/buckets/test-bucket/storageLayout"
                ),
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/storageLayout"
                ),
            ),
        ]

        for tc in test_cases:
            with self.subTest(name=tc.name):
                if tc.setup_func:
                    tc.setup_func(self)

                context = self.mock_context()

                # Dynamically get the method from the servicer
                method = getattr(self.servicer, tc.method_name)

                start_time = time.time()
                result = method(tc.request, context)
                elapsed = time.time() - start_time

                self.assertIsNotNone(result)
                self.assertLess(elapsed, 0.5, "Should take less than 0.5s")

                if tc.verify_func:
                    tc.verify_func(self, result)

    def test_stall_behaviors(self):
        """Table-driven test for various stall behaviors across API methods."""
        test_cases = [
            ApiTestCase(
                name="create_folder_stall_500ms",
                method_name="CreateFolder",
                request=storage_control_pb2.CreateFolderRequest(
                    parent="projects/_/buckets/test-bucket",
                    folder_id="create-stall-500ms",
                ),
                verify_func=lambda self, res: self.assertEqual(
                    res.name,
                    "projects/_/buckets/test-bucket/folders/create-stall-500ms",
                ),
            ),
            ApiTestCase(
                name="create_folder_stall_1s",
                method_name="CreateFolder",
                request=storage_control_pb2.CreateFolderRequest(
                    parent="projects/_/buckets/test-bucket", folder_id="create-stall-1s"
                ),
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/folders/create-stall-1s"
                ),
            ),
            ApiTestCase(
                name="delete_folder_stall_1s",
                method_name="DeleteFolder",
                setup_func=lambda self: self._create_folder("delete-stall-1s"),
                request=storage_control_pb2.DeleteFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/delete-stall-1s"
                ),
                verify_func=lambda self, res: self.assertIsInstance(
                    res, empty_pb2.Empty
                ),
            ),
            ApiTestCase(
                name="get_folder_stall_1s",
                method_name="GetFolder",
                setup_func=lambda self: self._create_folder("get-stall-1s"),
                request=storage_control_pb2.GetFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/get-stall-1s"
                ),
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/folders/get-stall-1s"
                ),
            ),
            ApiTestCase(
                name="list_folders_stall_1s",
                method_name="ListFolders",
                setup_func=lambda self: self._create_folder("list-stall-1s"),
                request=storage_control_pb2.ListFoldersRequest(
                    parent="projects/_/buckets/test-bucket"
                ),
                verify_func=lambda self, res: self.assertGreaterEqual(
                    len(res.folders), 1
                ),
            ),
            ApiTestCase(
                name="rename_folder_stall_1s",
                method_name="RenameFolder",
                setup_func=lambda self: self._create_folder("rename-src-stall-1s"),
                request=storage_control_pb2.RenameFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/rename-src-stall-1s",
                    destination_folder_id="projects/_/buckets/test-bucket/folders/rename-dst-stall-1s",
                ),
                verify_func=lambda self, res: self.assertEqual(
                    res.name,
                    "projects/_/buckets/test-bucket/folders/rename-dst-stall-1s",
                ),
            ),
            ApiTestCase(
                name="get_storage_layout_stall_1s",
                method_name="GetStorageLayout",
                request=storage_control_pb2.GetStorageLayoutRequest(
                    name="projects/_/buckets/test-bucket/storageLayout"
                ),
                verify_func=lambda self, res: self.assertEqual(res.location, "US"),
            ),
        ]

        for tc in test_cases:
            with self.subTest(name=tc.name):
                if tc.setup_func:
                    tc.setup_func(self)

                # Determine instruction based on test name
                instruction = "stall-for-1s"
                expected_stall = 1.0
                if "500ms" in tc.name:
                    instruction = "stall-for-500ms"
                    expected_stall = 0.5

                metadata = [("x-goog-emulator-instructions", instruction)]
                context = self.mock_context(metadata)

                # Dynamically get the method from the servicer
                method = getattr(self.servicer, tc.method_name)

                start_time = time.time()
                result = method(tc.request, context)
                elapsed = time.time() - start_time

                self.assertIsNotNone(result)
                self.assertGreaterEqual(
                    elapsed,
                    expected_stall,
                    f"Should stall for at least {expected_stall}s",
                )

                if tc.verify_func:
                    tc.verify_func(self, result)

    def test_multiple_stalls_and_no_stall(self):
        """Test that stall happens twice with metadata and not without."""
        metadata = [("x-goog-emulator-instructions", "stall-for-1s")]

        # First call with stall metadata
        req1 = storage_control_pb2.CreateFolderRequest(
            parent="projects/_/buckets/test-bucket", folder_id="test-folder-multi-1"
        )
        start_time = time.time()
        self.servicer.CreateFolder(req1, self.mock_context(metadata))
        elapsed1 = time.time() - start_time
        self.assertGreaterEqual(elapsed1, 1.0)

        # Second call with stall metadata
        req2 = storage_control_pb2.CreateFolderRequest(
            parent="projects/_/buckets/test-bucket", folder_id="test-folder-multi-2"
        )
        start_time = time.time()
        self.servicer.CreateFolder(req2, self.mock_context(metadata))
        elapsed2 = time.time() - start_time
        self.assertGreaterEqual(elapsed2, 1.0)

        # Third call without stall metadata
        req3 = storage_control_pb2.CreateFolderRequest(
            parent="projects/_/buckets/test-bucket", folder_id="test-folder-multi-3"
        )
        start_time = time.time()
        self.servicer.CreateFolder(req3, self.mock_context())
        elapsed3 = time.time() - start_time
        self.assertLess(elapsed3, 1.0)


if __name__ == "__main__":
    unittest.main()
