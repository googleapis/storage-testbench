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

"""Helper class for rewrite operations."""

import hashlib
import json
import types
import uuid

import crc32c
import flask
from google.protobuf import json_format

from google.storage.v2 import storage_pb2
import testbench


class Rewrite(types.SimpleNamespace):
    """The state for a single object rewrite operation.

    Object rewrites may require multiple RPCs to complete, we need an object to
    keep the state of these rewrites, as the data used in the initial RPC is
    not provided in future RPCs, but it is needed to complete the rewrite."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    # The minimum number of bytes rewritten in each iteration.  For testing
    # purposes, callers can create rewrite operations that set a maximum on
    # the number of bytes rewritten in each call.  However, this maximum must
    # be at least 1 MiB.
    MIN_REWRITE_BYTES = 1024 * 1024

    @classmethod
    def init_rest(
        cls, request, src_bucket_name, src_object_name, dst_bucket_name, dst_object_name
    ):
        fake_request = testbench.common.FakeRequest(
            args=request.args.to_dict(),
            headers={
                key.lower(): value
                for key, value in request.headers.items()
                if key.lower().startswith("x-")
            },
            data=request.data,
        )
        max_bytes_rewritten_per_call = min(
            int(
                fake_request.args.get("maxBytesRewrittenPerCall", cls.MIN_REWRITE_BYTES)
            ),
            cls.MIN_REWRITE_BYTES,
        )
        token = hashlib.sha256(
            (
                "%s/o/%s/rewriteTo/b/%s/o/%s"
                % (src_bucket_name, src_object_name, dst_bucket_name, dst_object_name)
            ).encode("utf-8")
        ).hexdigest()
        return cls(
            request=fake_request,
            src_bucket_name=src_bucket_name,
            src_object_name=src_object_name,
            dst_bucket_name=dst_bucket_name,
            dst_object_name=dst_object_name,
            token=token,
            media=b"",
            max_bytes_rewritten_per_call=max_bytes_rewritten_per_call,
        )
