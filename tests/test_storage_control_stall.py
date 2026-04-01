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
import time
import unittest
import unittest.mock
from typing import Any, Callable, Optional

import grpc
from google.protobuf import empty_pb2

import testbench
from google.storage.control.v2 import storage_control_pb2


@dataclasses.dataclass
class StallTestCase:
    name: str
    method_name: str
    request: Any
    instructions: Optional[str]
    min_duration: Optional[float]
    max_duration: Optional[float]
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
        self.db = testbench.database.Database.init()
        self.servicer = testbench.grpc_server.StorageControlServicer(
            self.db, echo_metadata=False
        )

    def _create_folder(self, folder_id):
        request = storage_control_pb2.CreateFolderRequest(
            parent="projects/_/buckets/test-bucket", folder_id=folder_id
        )
        self.servicer.CreateFolder(request, self.mock_context())

    def test_stall_behaviors(self):
        """Table-driven test for various stall behaviors across API methods."""
        test_cases = [
            # CreateFolder
            StallTestCase(
                name="create_folder_no_stall",
                method_name="CreateFolder",
                request=storage_control_pb2.CreateFolderRequest(
                    parent="projects/_/buckets/test-bucket", folder_id="create-no-stall"
                ),
                instructions=None,
                min_duration=None,
                max_duration=0.5,
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/folders/create-no-stall"
                ),
            ),
            StallTestCase(
                name="create_folder_stall_1s",
                method_name="CreateFolder",
                request=storage_control_pb2.CreateFolderRequest(
                    parent="projects/_/buckets/test-bucket", folder_id="create-stall-1s"
                ),
                instructions="stall-for-1s",
                min_duration=1.0,
                max_duration=None,
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/folders/create-stall-1s"
                ),
            ),
            # DeleteFolder
            StallTestCase(
                name="delete_folder_no_stall",
                method_name="DeleteFolder",
                setup_func=lambda self: self._create_folder("delete-no-stall"),
                request=storage_control_pb2.DeleteFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/delete-no-stall"
                ),
                instructions=None,
                min_duration=None,
                max_duration=0.5,
                verify_func=lambda self, res: self.assertIsInstance(
                    res, empty_pb2.Empty
                ),
            ),
            StallTestCase(
                name="delete_folder_stall_1s",
                method_name="DeleteFolder",
                setup_func=lambda self: self._create_folder("delete-stall-1s"),
                request=storage_control_pb2.DeleteFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/delete-stall-1s"
                ),
                instructions="stall-for-1s",
                min_duration=1.0,
                max_duration=None,
                verify_func=lambda self, res: self.assertIsInstance(
                    res, empty_pb2.Empty
                ),
            ),
            # GetFolder
            StallTestCase(
                name="get_folder_no_stall",
                method_name="GetFolder",
                setup_func=lambda self: self._create_folder("get-no-stall"),
                request=storage_control_pb2.GetFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/get-no-stall"
                ),
                instructions=None,
                min_duration=None,
                max_duration=0.5,
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/folders/get-no-stall"
                ),
            ),
            StallTestCase(
                name="get_folder_stall_1s",
                method_name="GetFolder",
                setup_func=lambda self: self._create_folder("get-stall-1s"),
                request=storage_control_pb2.GetFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/get-stall-1s"
                ),
                instructions="stall-for-1s",
                min_duration=1.0,
                max_duration=None,
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/folders/get-stall-1s"
                ),
            ),
            # ListFolders
            StallTestCase(
                name="list_folders_no_stall",
                method_name="ListFolders",
                setup_func=lambda self: self._create_folder("list-no-stall"),
                request=storage_control_pb2.ListFoldersRequest(
                    parent="projects/_/buckets/test-bucket"
                ),
                instructions=None,
                min_duration=None,
                max_duration=0.5,
                verify_func=lambda self, res: self.assertGreaterEqual(
                    len(res.folders), 1
                ),
            ),
            StallTestCase(
                name="list_folders_stall_1s",
                method_name="ListFolders",
                setup_func=lambda self: self._create_folder("list-stall-1s"),
                request=storage_control_pb2.ListFoldersRequest(
                    parent="projects/_/buckets/test-bucket"
                ),
                instructions="stall-for-1s",
                min_duration=1.0,
                max_duration=None,
                verify_func=lambda self, res: self.assertGreaterEqual(
                    len(res.folders), 1
                ),
            ),
            # RenameFolder
            StallTestCase(
                name="rename_folder_no_stall",
                method_name="RenameFolder",
                setup_func=lambda self: self._create_folder("rename-src-no-stall"),
                request=storage_control_pb2.RenameFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/rename-src-no-stall",
                    destination_folder_id="projects/_/buckets/test-bucket/folders/rename-dst-no-stall",
                ),
                instructions=None,
                min_duration=None,
                max_duration=0.5,
                verify_func=lambda self, res: self.assertEqual(
                    res.name,
                    "projects/_/buckets/test-bucket/folders/rename-src-no-stall",
                ),
            ),
            StallTestCase(
                name="rename_folder_stall_1s",
                method_name="RenameFolder",
                setup_func=lambda self: self._create_folder("rename-src-stall-1s"),
                request=storage_control_pb2.RenameFolderRequest(
                    name="projects/_/buckets/test-bucket/folders/rename-src-stall-1s",
                    destination_folder_id="projects/_/buckets/test-bucket/folders/rename-dst-stall-1s",
                ),
                instructions="stall-for-1s",
                min_duration=1.0,
                max_duration=None,
                verify_func=lambda self, res: self.assertEqual(
                    res.name,
                    "projects/_/buckets/test-bucket/folders/rename-src-stall-1s",
                ),
            ),
            # GetStorageLayout
            StallTestCase(
                name="get_storage_layout_no_stall",
                method_name="GetStorageLayout",
                request=storage_control_pb2.GetStorageLayoutRequest(
                    name="projects/_/buckets/test-bucket/storageLayout"
                ),
                instructions=None,
                min_duration=None,
                max_duration=0.5,
                verify_func=lambda self, res: self.assertEqual(
                    res.name, "projects/_/buckets/test-bucket/storageLayout"
                ),
            ),
            StallTestCase(
                name="get_storage_layout_stall_1s",
                method_name="GetStorageLayout",
                request=storage_control_pb2.GetStorageLayoutRequest(
                    name="projects/_/buckets/test-bucket/storageLayout"
                ),
                instructions="stall-for-1s",
                min_duration=1.0,
                max_duration=None,
                verify_func=lambda self, res: self.assertEqual(res.location, "US"),
            ),
        ]

        for tc in test_cases:
            with self.subTest(name=tc.name):
                if tc.setup_func:
                    tc.setup_func(self)

                metadata = (
                    [("x-goog-emulator-instructions", tc.instructions)]
                    if tc.instructions
                    else []
                )
                context = self.mock_context(metadata)

                # Dynamically get the method from the servicer
                method = getattr(self.servicer, tc.method_name)

                start_time = time.time()
                result = method(tc.request, context)
                elapsed = time.time() - start_time

                self.assertIsNotNone(result)
                if tc.min_duration is not None:
                    self.assertGreaterEqual(
                        elapsed,
                        tc.min_duration,
                        f"Should stall for at least {tc.min_duration}s",
                    )
                if tc.max_duration is not None:
                    self.assertLess(
                        elapsed,
                        tc.max_duration,
                        f"Should not stall longer than {tc.max_duration}s",
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
