# Storage Control API Stall Implementation - Validation Guide

## Overview

This document describes how to validate the stall functionality for the Storage Control API that was implemented in this branch.

## What Was Implemented

1. **Protobuf Generation**: Added `google/storage/control/v2/storage_control.proto` to the proto generation pipeline
2. **Database Layer**: Added folder storage **capabilities** to `testbench/database.py`
3. **gRPC Service**: Implemented `StorageControlServicer` in `testbench/grpc_server.py` with stall support
4. **Stall Functionality**: Added `_apply_stall()` method that intercepts folder API calls and applies delays based on `x-goog-emulator-instructions` metadata

## Stall Instructions Supported

The implementation supports the following stall instructions via gRPC metadata header `x-goog-emulator-instructions`:

- `stall-always`: Stalls for 10 seconds at the beginning of the request
- `stall-for-Ns`: Stalls for N seconds (e.g., `stall-for-3s` stalls for 3 seconds)

## Supported Operations

All Storage Control API folder operations support stall:
- `CreateFolder`
- `DeleteFolder`
- `GetFolder`
- `ListFolders`
- `RenameFolder`

## Running the Tests

### Prerequisites

1. Ensure you're in a virtual environment:
```bash
source ../venv-storage-testbench/bin/activate
```

### Quick Validation (Non-Stall Test)

Run this test to verify basic functionality (~1 second):
```bash
python -m unittest tests.test_storage_control_stall.TestStorageControlStall.test_create_folder_no_stall -v
```

### Stall Functionality Tests

Run these tests to verify stall functionality (each takes several seconds due to intentional delays):

**Custom duration stall (3 seconds):**
```bash
python -m unittest tests.test_storage_control_stall.TestStorageControlStall.test_create_folder_stall_custom_duration -v
```

**Delete with stall (2 seconds):**
```bash
python -m unittest tests.test_storage_control_stall.TestStorageControlStall.test_delete_folder_stall -v
```

**Get with stall (5 seconds):**
```bash
python -m unittest tests.test_storage_control_stall.TestStorageControlStall.test_get_folder_stall -v
```

**List with stall (4 seconds):**
```bash
python -m unittest tests.test_storage_control_stall.TestStorageControlStall.test_list_folders_stall -v
```

**Rename with stall (6 seconds):**
```bash
python -m unittest tests.test_storage_control_stall.TestStorageControlStall.test_rename_folder_stall -v
```

### Full Test Suite

Run all tests at once (takes ~30+ seconds):
```bash
python -m unittest tests.test_storage_control_stall -v
```

**Note:** The `test_create_folder_stall_always` test takes 10+ seconds as it uses the default stall duration.

## Manual Testing with gRPC Client

You can also test using a Python gRPC client:

```python
import grpc
from google.storage.control.v2 import storage_control_pb2, storage_control_pb2_grpc
import time

# Connect to testbench
channel = grpc.insecure_channel('localhost:9099')  # Use actual gRPC port
stub = storage_control_pb2_grpc.StorageControlStub(channel)

# Test with stall-for-5s instruction
metadata = [('x-goog-emulator-instructions', 'stall-for-5s')]
request = storage_control_pb2.CreateFolderRequest()
request.parent = "projects/_/buckets/test-bucket"
request.folder_id = "my-test-folder"

start = time.time()
folder = stub.CreateFolder(request, metadata=metadata)
elapsed = time.time() - start

print(f"Request took {elapsed:.2f} seconds")
print(f"Created folder: {folder.name}")
```

## Expected Test Results

✅ **Success Criteria:**
- Non-stall tests complete in < 1 second
- `stall-always` tests take >= 10 seconds
- `stall-for-Ns` tests take >= N seconds (within 1-2 seconds tolerance)
- Folder operations (create, delete, get, list, rename) all work correctly
- Stall applies before the operation executes

## Integration with Existing Tests

The implementation doesn't affect existing Storage API tests. You can verify this by running:

```bash
python -m unittest discover -s tests/ -p "test_grpc_server.py" -v
```

This should pass without any issues.

## Files Modified

- `update-protos.sh`: Added storage_control.proto to the generation list
- `testbench/database.py`: Added folder storage methods
- `testbench/grpc_server.py`: Added StorageControlServicer with stall support
- `tests/test_storage_control_stall.py`: Comprehensive test suite for stall functionality
- `google/storage/control/v2/`: Generated protobuf files (storage_control_pb2.py, storage_control_pb2_grpc.py)

## Troubleshooting

**Issue: ImportError for storage_control_pb2**
- Solution: Regenerate protobuf files: `source ../venv-storage-testbench/bin/activate && bash update-protos.sh`

**Issue: Tests timing out**
- Solution: Increase timeout values in test runner, stall tests are intentionally slow

**Issue: "Protocol message Folder has no field 'bucket'"**
- Solution: This was fixed - Folder only has fields: name, metageneration, create_time, update_time, pending_rename_info

## Architecture Notes

The stall implementation uses `time.sleep()` which blocks the current thread. This is appropriate for:
- Testing timeout handling
- Simulating slow backends
- Reproducing transient network conditions

The implementation extracts stall instructions from gRPC metadata via `testbench.common.extract_instruction()`, which checks for the `x-goog-emulator-instructions` header in the invocation metadata.
