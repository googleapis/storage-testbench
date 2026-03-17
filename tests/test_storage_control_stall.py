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

import time
import unittest
import unittest.mock

import grpc

import testbench
from google.protobuf import empty_pb2
from google.storage.control.v2 import storage_control_pb2


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

    def test_create_folder_no_stall(self):
        """Test folder creation without stall instruction."""
        request = storage_control_pb2.CreateFolderRequest()
        request.parent = "projects/_/buckets/test-bucket"
        request.folder_id = "test-folder"
        
        context = self.mock_context()
        
        start_time = time.time()
        folder = self.servicer.CreateFolder(request, context)
        elapsed = time.time() - start_time
        
        self.assertIsNotNone(folder)
        self.assertEqual(folder.name, "projects/_/buckets/test-bucket/folders/test-folder")
        self.assertLess(elapsed, 1.0, "Should complete quickly without stall")

    def test_create_folder_stall_1s(self):
        """Test folder creation with 1s stall instruction."""
        request = storage_control_pb2.CreateFolderRequest()
        request.parent = "projects/_/buckets/test-bucket"
        request.folder_id = "test-folder-stall"
        
        metadata = [("x-goog-emulator-instructions", "stall-for-1s")]
        context = self.mock_context(metadata)
        
        start_time = time.time()
        folder = self.servicer.CreateFolder(request, context)
        elapsed = time.time() - start_time
        
        self.assertIsNotNone(folder)
        self.assertEqual(folder.name, "projects/_/buckets/test-bucket/folders/test-folder-stall")
        self.assertGreaterEqual(elapsed, 1.0, "Should stall for at least 1 second")

    def test_create_folder_stall_custom_duration(self):
        """Test folder creation with custom stall duration."""
        request = storage_control_pb2.CreateFolderRequest()
        request.parent = "projects/_/buckets/test-bucket"
        request.folder_id = "test-folder-custom-stall"
        
        metadata = [("x-goog-emulator-instructions", "stall-for-2s")]
        context = self.mock_context(metadata)
        
        start_time = time.time()
        folder = self.servicer.CreateFolder(request, context)
        elapsed = time.time() - start_time
        
        self.assertIsNotNone(folder)
        self.assertEqual(folder.name, "projects/_/buckets/test-bucket/folders/test-folder-custom-stall")
        self.assertGreaterEqual(elapsed, 2.0, "Should stall for at least 2 seconds")
        self.assertLess(elapsed, 3.0, "Should not stall longer than 3 seconds")

    def test_delete_folder_stall(self):
        """Test folder deletion with stall instruction."""
        # First create a folder
        create_request = storage_control_pb2.CreateFolderRequest()
        create_request.parent = "projects/_/buckets/test-bucket"
        create_request.folder_id = "test-folder-delete"
        context = self.mock_context()
        self.servicer.CreateFolder(create_request, context)
        
        # Now delete it with stall
        delete_request = storage_control_pb2.DeleteFolderRequest()
        delete_request.name = "projects/_/buckets/test-bucket/folders/test-folder-delete"
        
        metadata = [("x-goog-emulator-instructions", "stall-for-1s")]
        context_stall = self.mock_context(metadata)
        
        start_time = time.time()
        result = self.servicer.DeleteFolder(delete_request, context_stall)
        elapsed = time.time() - start_time
        
        self.assertIsInstance(result, empty_pb2.Empty)
        self.assertGreaterEqual(elapsed, 1.0, "Should stall for at least 1 second")

    def test_get_folder_stall(self):
        """Test get folder with stall instruction."""
        # First create a folder
        create_request = storage_control_pb2.CreateFolderRequest()
        create_request.parent = "projects/_/buckets/test-bucket"
        create_request.folder_id = "test-folder-get"
        context = self.mock_context()
        created_folder = self.servicer.CreateFolder(create_request, context)
        
        # Now get it with stall
        get_request = storage_control_pb2.GetFolderRequest()
        get_request.name = "projects/_/buckets/test-bucket/folders/test-folder-get"
        
        metadata = [("x-goog-emulator-instructions", "stall-for-1s")]
        context_stall = self.mock_context(metadata)
        
        start_time = time.time()
        folder = self.servicer.GetFolder(get_request, context_stall)
        elapsed = time.time() - start_time
        
        self.assertIsNotNone(folder)
        self.assertEqual(folder.name, "projects/_/buckets/test-bucket/folders/test-folder-get")
        self.assertGreaterEqual(elapsed, 1.0, "Should stall for at least 1 second")

    def test_list_folders_stall(self):
        """Test list folders with stall instruction."""
        # Create some folders
        for i in range(3):
            create_request = storage_control_pb2.CreateFolderRequest()
            create_request.parent = "projects/_/buckets/test-bucket"
            create_request.folder_id = f"test-folder-list-{i}"
            context = self.mock_context()
            self.servicer.CreateFolder(create_request, context)
        
        # List with stall
        list_request = storage_control_pb2.ListFoldersRequest()
        list_request.parent = "projects/_/buckets/test-bucket"
        
        metadata = [("x-goog-emulator-instructions", "stall-for-1s")]
        context_stall = self.mock_context(metadata)
        
        start_time = time.time()
        response = self.servicer.ListFolders(list_request, context_stall)
        elapsed = time.time() - start_time
        
        self.assertIsNotNone(response)
        self.assertGreaterEqual(len(response.folders), 3)
        self.assertGreaterEqual(elapsed, 1.0, "Should stall for at least 1 second")

    def test_rename_folder_stall(self):
        """Test rename folder with stall instruction."""
        # Create a folder
        create_request = storage_control_pb2.CreateFolderRequest()
        create_request.parent = "projects/_/buckets/test-bucket"
        create_request.folder_id = "test-folder-rename-src"
        context = self.mock_context()
        self.servicer.CreateFolder(create_request, context)
        
        # Rename with stall
        rename_request = storage_control_pb2.RenameFolderRequest()
        rename_request.name = "projects/_/buckets/test-bucket/folders/test-folder-rename-src"
        rename_request.destination_folder_id = "projects/_/buckets/test-bucket/test-folder-rename-dst"
        
        metadata = [("x-goog-emulator-instructions", "stall-for-1s")]
        context_stall = self.mock_context(metadata)
        
        start_time = time.time()
        folder = self.servicer.RenameFolder(rename_request, context_stall)
        elapsed = time.time() - start_time
        
        self.assertIsNotNone(folder)
        self.assertGreaterEqual(elapsed, 1.0, "Should stall for at least 1 second")

    def test_multiple_stalls_and_no_stall(self):
        """Test that stall happens twice with metadata and not without."""
        # First call with stall metadata
        request1 = storage_control_pb2.CreateFolderRequest()
        request1.parent = "projects/_/buckets/test-bucket"
        request1.folder_id = "test-folder-multi-1"
        
        metadata = [("x-goog-emulator-instructions", "stall-for-1s")]
        context_stall = self.mock_context(metadata)
        
        start_time = time.time()
        folder1 = self.servicer.CreateFolder(request1, context_stall)
        elapsed1 = time.time() - start_time
        
        self.assertIsNotNone(folder1)
        self.assertGreaterEqual(elapsed1, 1.0, "First call should stall for at least 1 second")
        
        # Second call with stall metadata
        request2 = storage_control_pb2.CreateFolderRequest()
        request2.parent = "projects/_/buckets/test-bucket"
        request2.folder_id = "test-folder-multi-2"
        
        context_stall2 = self.mock_context(metadata)
        
        start_time = time.time()
        folder2 = self.servicer.CreateFolder(request2, context_stall2)
        elapsed2 = time.time() - start_time
        
        self.assertIsNotNone(folder2)
        self.assertGreaterEqual(elapsed2, 1.0, "Second call should stall for at least 1 second")
        
        # Third call without stall metadata
        request3 = storage_control_pb2.CreateFolderRequest()
        request3.parent = "projects/_/buckets/test-bucket"
        request3.folder_id = "test-folder-multi-3"
        
        context_no_stall = self.mock_context()
        
        start_time = time.time()
        folder3 = self.servicer.CreateFolder(request3, context_no_stall)
        elapsed3 = time.time() - start_time
        
        self.assertIsNotNone(folder3)
        self.assertLess(elapsed3, 1.0, "Third call should complete quickly without stall")

    def test_get_storage_layout_no_stall(self):
        """Test get storage layout without stall instruction."""
        request = storage_control_pb2.GetStorageLayoutRequest()
        request.name = "projects/_/buckets/test-bucket/storageLayout"
        
        context = self.mock_context()
        
        start_time = time.time()
        layout = self.servicer.GetStorageLayout(request, context)
        elapsed = time.time() - start_time
        
        self.assertIsNotNone(layout)
        self.assertEqual(layout.name, "projects/_/buckets/test-bucket/storageLayout")
        self.assertLess(elapsed, 1.0, "Should complete quickly without stall")

    def test_get_storage_layout_stall(self):
        """Test get storage layout with stall instruction."""
        request = storage_control_pb2.GetStorageLayoutRequest()
        request.name = "projects/_/buckets/test-bucket/storageLayout"
        
        metadata = [("x-goog-emulator-instructions", "stall-for-1s")]
        context_stall = self.mock_context(metadata)
        
        start_time = time.time()
        layout = self.servicer.GetStorageLayout(request, context_stall)
        elapsed = time.time() - start_time
        
        self.assertIsNotNone(layout)
        self.assertEqual(layout.name, "projects/_/buckets/test-bucket/storageLayout")
        self.assertEqual(layout.location, "US")
        self.assertEqual(layout.location_type, "multi-region")
        self.assertFalse(layout.hierarchical_namespace.enabled)
        self.assertGreaterEqual(elapsed, 1.0, "Should stall for at least 1 second")


if __name__ == "__main__":
    unittest.main()
