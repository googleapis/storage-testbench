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

import types
import uuid

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
    def _normalize_max_bytes(cls, max_bytes):
        return max(
            int(cls.MIN_REWRITE_BYTES if max_bytes is None else max_bytes),
            cls.MIN_REWRITE_BYTES,
        )

    @classmethod
    def _token(cls):
        return uuid.uuid4().hex

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
        return cls(
            request=request,
            src_bucket_name=src_bucket_name,
            src_object_name=src_object_name,
            dst_bucket_name=dst_bucket_name,
            dst_object_name=dst_object_name,
            token=cls._token(),
            media=b"",
            max_bytes_rewritten_per_call=cls._normalize_max_bytes(
                fake_request.args.get("maxBytesRewrittenPerCall")
            ),
        )

    @classmethod
    def init_grpc(cls, request, context):
        if not request.source_bucket.startswith("projects/_/buckets/"):
            return testbench.error.invalid(
                "invalid or missing source bucket name in rewrite request", context
            )
        src_bucket_name = testbench.common.bucket_name_from_proto(request.source_bucket)
        if src_bucket_name is None or len(src_bucket_name) == 0:
            return testbench.error.invalid(
                "invalid or missing source bucket name in rewrite request", context
            )
        src_object_name = request.source_object
        if src_object_name is None or len(src_object_name) == 0:
            return testbench.error.invalid(
                "invalid or missing source object name in rewrite request", context
            )
        if request.destination is None:
            return testbench.error.invalid(
                "missing destination object in rewrite request", context
            )
        if not request.destination.bucket.startswith("projects/_/buckets/"):
            return testbench.error.invalid(
                "invalid or missing source bucket name in rewrite request", context
            )
        dst_bucket_name = testbench.common.bucket_name_from_proto(
            request.destination.bucket
        )
        if dst_bucket_name is None or len(dst_bucket_name) == 0:
            return testbench.error.invalid(
                "invalid or missing destination bucket name in rewrite request", context
            )
        dst_object_name = request.destination.name
        if dst_object_name is None or len(dst_object_name) == 0:
            return testbench.error.invalid(
                "invalid or missing destination object name in rewrite request", context
            )
        return cls(
            request=request,
            src_bucket_name=src_bucket_name,
            src_object_name=src_object_name,
            dst_bucket_name=dst_bucket_name,
            dst_object_name=dst_object_name,
            token=cls._token(),
            media=b"",
            max_bytes_rewritten_per_call=cls._normalize_max_bytes(
                request.max_bytes_rewritten_per_call
            ),
        )
