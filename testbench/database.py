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

import collections
import json
import os
import re
import uuid

from schema import Schema, SchemaError, And, Use
from google.cloud.storage_v1.proto import storage_pb2 as storage_pb2

import gcs
import testbench


class Database:
    def __init__(
        self,
        buckets,
        objects,
        live_generations,
        uploads,
        rewrites,
        retry_tests,
        supported_methods,
    ):
        self.buckets = buckets
        self.objects = objects
        self.live_generations = live_generations
        self.uploads = uploads
        self.rewrites = rewrites
        self.retry_tests = retry_tests
        self.supported_methods = supported_methods

    @classmethod
    def init(cls):
        return cls({}, {}, {}, {}, {}, {}, [])

    def clear(self):
        """Clear all data except for the supported method list."""
        self.buckets = {}
        self.objects = {}
        self.live_generations = {}
        self.uploads = {}
        self.rewrites = {}
        self.retry_tests = {}
        # The list of supported methods for `retry_test` is defined via flask
        # decorators, it should remain unchanged after the test or application
        # is initialized. Arguably this means it should be in a global variable.
        #   TODO(#27) - maybe `self.supported_methods` should be a global

    # === BUCKET === #

    def __check_bucket_metageneration(self, request, bucket, context):
        metageneration = bucket.metadata.metageneration
        match, not_match = testbench.generation.extract_precondition(
            request, True, False, context
        )
        testbench.generation.check_precondition(
            metageneration, match, not_match, True, context
        )

    def get_bucket_without_generation(self, bucket_name, context):
        bucket = self.buckets.get(bucket_name)
        if bucket is None:
            testbench.error.notfound("Bucket %s" % bucket_name, context)
        return bucket

    def insert_bucket(self, request, bucket, context):
        self.buckets[bucket.metadata.name] = bucket
        self.objects[bucket.metadata.name] = {}
        self.live_generations[bucket.metadata.name] = {}

    def get_bucket(self, request, bucket_name, context):
        bucket = self.get_bucket_without_generation(bucket_name, context)
        self.__check_bucket_metageneration(request, bucket, context)
        return bucket

    def list_bucket(self, request, project_id, context):
        if project_id is None or project_id.endswith("-"):
            testbench.error.invalid("Project id %s" % project_id, context)
        return self.buckets.values()

    def delete_bucket(self, request, bucket_name, context):
        bucket = self.get_bucket(request, bucket_name, context)
        if len(self.live_generations[bucket.metadata.name]) > 0:
            testbench.error.invalid("Deleting non-empty bucket", context)
        del self.buckets[bucket.metadata.name]
        del self.objects[bucket.metadata.name]
        del self.live_generations[bucket.metadata.name]

    def insert_test_bucket(self, context):
        """Automatically create a bucket if needed.

        Many of the integration tests for `google-cloud-cpp` assume a
        well-known bucket already exists. This function creates a bucket
        based on the `GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME`, which
        also happens to be the environment variable used to configure this
        bucket name in said integration tests."""
        bucket_name = os.environ.get("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)
        if bucket_name is None:
            return
        if self.buckets.get(bucket_name) is None:
            request = testbench.common.FakeRequest(
                args={}, data=json.dumps({"name": bucket_name})
            )
            bucket_test, _ = gcs.bucket.Bucket.init(request, context)
            self.insert_bucket(request, bucket_test, context)
            bucket_test.metadata.metageneration = 4
            bucket_test.metadata.versioning.enabled = True

    # === OBJECT === #

    def __get_bucket_for_object(self, bucket_name, context):
        bucket = self.objects.get(bucket_name)
        if bucket is None:
            testbench.error.notfound("Bucket %s" % bucket_name, context)
        return bucket

    @classmethod
    def __extract_list_object_request(cls, request, context):
        delimiter, prefix, versions = "", "", False
        start_offset, end_offset = "", None
        include_trailing_delimiter = False
        # TODO(#27) - restore gRPC support for listing objects?
        delimiter = request.args.get("delimiter", "")
        prefix = request.args.get("prefix", "")
        versions = request.args.get("versions", False, type=bool)
        start_offset = request.args.get("startOffset", "")
        end_offset = request.args.get("endOffset")
        include_trailing_delimiter = request.args.get("includeTrailingDelimiter", False)
        return (
            delimiter,
            prefix,
            versions,
            start_offset,
            end_offset,
            include_trailing_delimiter,
        )

    def list_object(self, request, bucket_name, context):
        bucket = self.__get_bucket_for_object(bucket_name, context)
        (
            delimiter,
            prefix,
            versions,
            start_offset,
            end_offset,
            include_trailing_delimiter,
        ) = self.__extract_list_object_request(request, context)
        items = []
        rest_onlys = []
        prefixes = set()
        for obj in bucket.values():
            generation = obj.metadata.generation
            name = obj.metadata.name
            if not versions and generation != self.live_generations[bucket_name].get(
                name
            ):
                continue
            if name.find(prefix) != 0:
                continue
            if name < start_offset:
                continue
            if end_offset and name >= end_offset:
                continue
            delimiter_index = name.find(delimiter, len(prefix))
            if delimiter != "" and delimiter_index > 0:
                prefixes.add(name[: delimiter_index + 1])
                if delimiter_index < len(name) - 1 or not include_trailing_delimiter:
                    continue
            items.append(obj.metadata)
            rest_onlys.append(obj.rest_only)
        return items, list(prefixes), rest_onlys

    def check_object_generation(
        self, request, bucket_name, object_name, is_source, context
    ):
        bucket = self.__get_bucket_for_object(bucket_name, context)
        generation = testbench.generation.extract_generation(
            request, is_source, context
        )
        if generation == 0:
            generation = self.live_generations[bucket_name].get(object_name, 0)
        match, not_match = testbench.generation.extract_precondition(
            request, False, is_source, context
        )
        testbench.generation.check_precondition(
            generation, match, not_match, False, context
        )
        blob = bucket.get("%s#%d" % (object_name, generation))
        metageneration = blob.metadata.metageneration if blob is not None else None
        match, not_match = testbench.generation.extract_precondition(
            request, True, is_source, context
        )
        testbench.generation.check_precondition(
            metageneration, match, not_match, True, context
        )
        return blob, generation

    def get_object(self, request, bucket_name, object_name, is_source, context):
        blob, generation = self.check_object_generation(
            request, bucket_name, object_name, is_source, context
        )
        if blob is None:
            if generation == 0:
                testbench.error.notfound(
                    "Live version of object %s" % object_name, context
                )
            else:
                testbench.error.notfound(
                    "Object %s with generation %d" % (object_name, generation), context
                )
        return blob

    def insert_object(self, request, bucket_name, blob, context):
        self.check_object_generation(
            request, bucket_name, blob.metadata.name, False, context
        )
        bucket = self.__get_bucket_for_object(bucket_name, context)
        name = blob.metadata.name
        generation = blob.metadata.generation
        bucket["%s#%d" % (name, generation)] = blob
        self.live_generations[bucket_name][name] = generation

    def delete_object(self, request, bucket_name, object_name, context):
        _ = self.get_object(request, bucket_name, object_name, False, context)
        generation = testbench.generation.extract_generation(request, False, context)
        live_generation = self.live_generations[bucket_name].get(object_name)
        if generation == 0 or live_generation == generation:
            self.live_generations[bucket_name].pop(object_name, None)
        if generation != 0:
            del self.objects[bucket_name]["%s#%d" % (object_name, generation)]

    # === UPLOAD === #

    def get_upload(self, upload_id, context):
        upload = self.uploads.get(upload_id)
        if upload is None:
            testbench.error.notfound("Upload %s" % upload_id, context)
        return upload

    def insert_upload(self, upload):
        self.uploads[upload.upload_id] = upload

    def delete_upload(self, upload_id, context):
        self.get_upload(upload_id, context)
        del self.uploads[upload_id]

    # === REWRITE === #

    def get_rewrite(self, token, context):
        rewrite = self.rewrites.get(token)
        if rewrite is None:
            testbench.error.notfound("Rewrite %s" % token, context)
        return rewrite

    def insert_rewrite(self, rewrite):
        self.rewrites[rewrite.token] = rewrite

    def delete_rewrite(self, token, context):
        self.get_rewrite(token, context)
        del self.rewrites[token]

    # ==== RETRY_TESTS ==== #

    @classmethod
    def __to_serializeable_retry_test(cls, retry_test):
        return {
            "id": retry_test["id"],
            "instructions": {
                key: list(value) for key, value in retry_test["instructions"].items()
            },
            "completed": retry_test["completed"],
        }

    def insert_supported_methods(self, methods):
        self.supported_methods.extend(methods)

    def get_retry_test(self, retry_test_id):
        retry_test = self.retry_tests.get(retry_test_id)
        if retry_test is None:
            testbench.error.notfound("Retry Test %s" % retry_test_id, context=None)
        return self.__to_serializeable_retry_test(retry_test)

    def __validate_instructions(self, instructions):
        expected_instructions_format = [
            testbench.common.retry_return_error_code.pattern,
            testbench.common.retry_return_error_connection.pattern,
            testbench.common.retry_return_error_after_bytes.pattern,
        ]
        search_expression = re.compile(
            "(%s)" % ")|(".join(expected_instructions_format)
        )
        expected_schema = Schema(
            {
                And(Use(str), lambda n: n in self.supported_methods): [
                    And(Use(str), lambda n: re.match(search_expression, n))
                ]
            }
        )
        try:
            expected_schema.validate(instructions)
        except SchemaError as e:
            testbench.error.invalid("Invalid format used: %s" % e, context=None)

    def insert_retry_test(self, instructions):
        self.__validate_instructions(instructions)
        retry_test_id = uuid.uuid4().hex
        self.retry_tests[retry_test_id] = {
            "id": retry_test_id,
            "instructions": {
                key: collections.deque(value) for key, value in instructions.items()
            },
            "completed": False,
        }
        return self.__to_serializeable_retry_test(self.retry_tests[retry_test_id])

    def has_instructions_retry_test(self, retry_test_id, method):
        self.get_retry_test(retry_test_id)
        if len(self.retry_tests[retry_test_id]["instructions"].get(method, [])) > 0:
            return True
        return False

    def peek_next_instruction(self, retry_test_id, method):
        self.get_retry_test(retry_test_id)
        if self.retry_tests[retry_test_id]["instructions"] and self.retry_tests[
            retry_test_id
        ]["instructions"].get(method, None):
            return self.retry_tests[retry_test_id]["instructions"][method][0]
        else:
            return None

    def dequeue_next_instruction(self, retry_test_id, method):
        self.get_retry_test(retry_test_id)
        next_instruction = self.retry_tests[retry_test_id]["instructions"][
            method
        ].popleft()
        instructions_left = 0
        for key, value in self.retry_tests[retry_test_id]["instructions"].items():
            instructions_left += len(value)
        if instructions_left == 0:
            self.retry_tests[retry_test_id]["completed"] = True
        return next_instruction

    def list_retry_tests(self):
        return [
            self.__to_serializeable_retry_test(x) for x in self.retry_tests.values()
        ]

    def delete_retry_test(self, retry_test_id):
        self.get_retry_test(retry_test_id)
        del self.retry_tests[retry_test_id]
