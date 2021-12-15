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
import threading
import uuid

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
        self._resources_lock = threading.RLock()
        self._buckets = buckets
        self._objects = objects
        self._live_generations = live_generations

        self._uploads_lock = threading.RLock()
        self._uploads = uploads

        self._rewrites_lock = threading.RLock()
        self._rewrites = rewrites

        self._retry_tests_lock = threading.RLock()
        self._retry_tests = retry_tests
        self._supported_methods = supported_methods

    @classmethod
    def init(cls):
        return cls({}, {}, {}, {}, {}, {}, [])

    def clear(self):
        """Clear all data except for the supported method list."""
        with self._resources_lock:
            self._buckets = {}
            self._objects = {}
            self._live_generations = {}
        with self._uploads_lock:
            self._uploads = {}
        with self._rewrites_lock:
            self._rewrites = {}
        with self._retry_tests_lock:
            self._retry_tests = {}
        # The list of supported methods for `retry_test` is defined via flask
        # decorators, it should remain unchanged after the test or application
        # is initialized. Arguably this means it should be in a global variable.
        #   TODO(#27) - maybe `self._supported_methods` should be a global

    # === BUCKET === #

    def __check_bucket_metageneration(self, request, bucket, context):
        metageneration = bucket.metadata.metageneration
        match, not_match = testbench.generation.extract_precondition(
            request, True, False, context
        )
        testbench.generation.check_precondition(
            metageneration, match, not_match, True, context
        )

    def __bucket_key(self, bucket_name, context):
        if context is not None:
            return bucket_name
        return testbench.common.bucket_name_to_proto(bucket_name)

    def get_bucket_without_generation(self, bucket_name, context):
        with self._resources_lock:
            bucket = self._buckets.get(self.__bucket_key(bucket_name, context))
            if bucket is None:
                testbench.error.notfound("Bucket %s" % bucket_name, context)
            return bucket

    def insert_bucket(self, request, bucket, context):
        with self._resources_lock:
            self._buckets[bucket.metadata.name] = bucket
            self._objects[bucket.metadata.name] = {}
            self._live_generations[bucket.metadata.name] = {}

    def get_bucket(self, request, bucket_name, context):
        with self._resources_lock:
            bucket = self.get_bucket_without_generation(bucket_name, context)
            self.__check_bucket_metageneration(request, bucket, context)
            return bucket

    def list_bucket(self, request, project_id, context):
        with self._resources_lock:
            if project_id is None or project_id.endswith("-"):
                testbench.error.invalid("Project id %s" % project_id, context)
            return self._buckets.values()

    def delete_bucket(self, request, bucket_name, context):
        with self._resources_lock:
            bucket = self.get_bucket(request, bucket_name, context)
            if len(self._live_generations[bucket.metadata.name]) > 0:
                testbench.error.invalid("Deleting non-empty bucket", context)
            del self._buckets[bucket.metadata.name]
            del self._objects[bucket.metadata.name]
            del self._live_generations[bucket.metadata.name]

    def insert_test_bucket(self):
        """Automatically create a bucket if needed.

        Many of the integration tests for `google-cloud-cpp` assume a
        well-known bucket already exists. This function creates a bucket
        based on the `GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME`, which
        also happens to be the environment variable used to configure this
        bucket name in said integration tests."""
        bucket_name = os.environ.get("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)
        if bucket_name is None:
            return
        with self._resources_lock:
            if self._buckets.get(self.__bucket_key(bucket_name, None)) is None:
                request = testbench.common.FakeRequest(
                    args={}, data=json.dumps({"name": bucket_name})
                )
                bucket_test, _ = gcs.bucket.Bucket.init(request, None)
                self.insert_bucket(request, bucket_test, None)
                bucket_test.metadata.metageneration = 4
                bucket_test.metadata.versioning.enabled = True

    # === OBJECT === #

    def __get_bucket_for_object(self, bucket_name, context):
        bucket = self._objects.get(self.__bucket_key(bucket_name, context))
        if bucket is None:
            testbench.error.notfound("Bucket %s" % bucket_name, context)
        return bucket

    @classmethod
    def __extract_list_object_request_grpc(cls, request):
        return (
            request.delimiter,
            request.prefix,
            request.versions,
            request.lexicographic_start,
            request.lexicographic_end,
            request.include_trailing_delimiter,
        )

    @classmethod
    def __extract_list_object_request(cls, request, context):
        if context is not None:
            return cls.__extract_list_object_request_grpc(request)
        delimiter, prefix, versions = "", "", False
        start_offset, end_offset = "", None
        include_trailing_delimiter = False
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

    def __get_live_generation(self, bucket_name, object_name, context):
        bucket_key = self.__bucket_key(bucket_name, context)
        return self._live_generations[bucket_key].get(object_name)

    def __set_live_generation(self, bucket_name, object_name, generation, context):
        bucket_key = self.__bucket_key(bucket_name, context)
        self._live_generations[bucket_key][object_name] = generation

    def __del_live_generation(self, bucket_name, object_name, context):
        bucket_key = self.__bucket_key(bucket_name, context)
        self._live_generations[bucket_key].pop(object_name, None)

    def list_object(self, request, bucket_name, context):
        with self._resources_lock:
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
            prefixes = set()
            for obj in bucket.values():
                generation = obj.metadata.generation
                name = obj.metadata.name
                if not versions and generation != self.__get_live_generation(
                    bucket_name, name, context
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
                    if (
                        delimiter_index < len(name) - 1
                        or not include_trailing_delimiter
                    ):
                        continue
                items.append(obj.metadata)
            items.sort(key=lambda item: item.name)
            return items, sorted(list(prefixes))

    def _check_object_generation(
        self, request, bucket_name, object_name, is_source, context
    ):
        bucket = self.__get_bucket_for_object(bucket_name, context)
        generation = testbench.generation.extract_generation(
            request, is_source, context
        )
        if generation == 0:
            generation = self.__get_live_generation(bucket_name, object_name, context)
            if generation is None:
                generation = 0
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
        return blob, generation, bucket

    def get_object(self, request, bucket_name, object_name, is_source, context):
        with self._resources_lock:
            blob, generation, _ = self._check_object_generation(
                request, bucket_name, object_name, is_source, context
            )
            if blob is None:
                if generation == 0:
                    testbench.error.notfound(
                        "Live version of object %s" % object_name, context
                    )
                else:
                    testbench.error.notfound(
                        "Object %s with generation %d" % (object_name, generation),
                        context,
                    )
            return blob

    def insert_object(self, request, bucket_name, blob, context):
        with self._resources_lock:
            name = blob.metadata.name
            _, _, bucket = self._check_object_generation(
                request, bucket_name, name, False, context
            )
            generation = blob.metadata.generation
            bucket["%s#%d" % (name, generation)] = blob
            self.__set_live_generation(bucket_name, name, generation, context)

    def delete_object(self, request, bucket_name, object_name, context):
        with self._resources_lock:
            _ = self.get_object(request, bucket_name, object_name, False, context)
            generation = testbench.generation.extract_generation(
                request, False, context
            )
            live_generation = self.__get_live_generation(
                bucket_name, object_name, context
            )
            if generation == 0 or live_generation == generation:
                self.__del_live_generation(bucket_name, object_name, context)
            if generation != 0:
                self._objects[self.__bucket_key(bucket_name, context)].pop(
                    "%s#%d" % (object_name, generation), None
                )

    # === UPLOAD === #

    def get_upload(self, upload_id, context):
        with self._uploads_lock:
            upload = self._uploads.get(upload_id)
            if upload is None:
                testbench.error.notfound("Upload %s" % upload_id, context)
            return upload

    def insert_upload(self, upload):
        with self._uploads_lock:
            self._uploads[upload.upload_id] = upload

    def delete_upload(self, upload_id, context):
        with self._uploads_lock:
            self.get_upload(upload_id, context)
            del self._uploads[upload_id]

    # === REWRITE === #

    def get_rewrite(self, token, context):
        with self._rewrites_lock:
            rewrite = self._rewrites.get(token)
            if rewrite is None:
                testbench.error.notfound("Rewrite %s" % token, context)
            return rewrite

    def insert_rewrite(self, rewrite):
        with self._rewrites_lock:
            self._rewrites[rewrite.token] = rewrite

    def delete_rewrite(self, token, context):
        with self._rewrites_lock:
            self.get_rewrite(token, context)
            del self._rewrites[token]

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

    def supported_methods(self):
        with self._retry_tests_lock:
            return self._supported_methods

    def insert_supported_methods(self, methods):
        with self._retry_tests_lock:
            self._supported_methods.extend(methods)

    def get_retry_test(self, retry_test_id):
        with self._retry_tests_lock:
            retry_test = self._retry_tests.get(retry_test_id)
            if retry_test is None:
                testbench.error.notfound("Retry Test %s" % retry_test_id, context=None)
            return self.__to_serializeable_retry_test(retry_test)

    def __validate_injected_failure_description(self, failure):
        for expr in [
            testbench.common.retry_return_error_code,
            testbench.common.retry_return_error_connection,
            testbench.common.retry_return_error_after_bytes,
            testbench.common.retry_return_short_response,
        ]:
            if expr.match(failure) is not None:
                return
        testbench.error.invalid("The fault injection request <%s>" % failure, None)

    def __validate_instructions(self, instructions):
        for method, failures in instructions.items():
            if method not in self._supported_methods:
                testbench.error.invalid(
                    "The requested method <%s> for fault injection" % method, None
                )
            for failure in failures:
                self.__validate_injected_failure_description(failure)

    def insert_retry_test(self, instructions):
        with self._retry_tests_lock:
            self.__validate_instructions(instructions)
            retry_test_id = uuid.uuid4().hex
            self._retry_tests[retry_test_id] = {
                "id": retry_test_id,
                "instructions": {
                    key: collections.deque(value) for key, value in instructions.items()
                },
                "completed": False,
            }
            return self.__to_serializeable_retry_test(self._retry_tests[retry_test_id])

    def has_instructions_retry_test(self, retry_test_id, method):
        with self._retry_tests_lock:
            self.get_retry_test(retry_test_id)
            if (
                len(self._retry_tests[retry_test_id]["instructions"].get(method, []))
                > 0
            ):
                return True
            return False

    def peek_next_instruction(self, retry_test_id, method):
        with self._retry_tests_lock:
            self.get_retry_test(retry_test_id)
            if self._retry_tests[retry_test_id]["instructions"] and self._retry_tests[
                retry_test_id
            ]["instructions"].get(method, None):
                return self._retry_tests[retry_test_id]["instructions"][method][0]
            else:
                return None

    def dequeue_next_instruction(self, retry_test_id, method):
        with self._retry_tests_lock:
            self.get_retry_test(retry_test_id)
            next_instruction = self._retry_tests[retry_test_id]["instructions"][
                method
            ].popleft()
            instructions_left = 0
            for key, value in self._retry_tests[retry_test_id]["instructions"].items():
                instructions_left += len(value)
            if instructions_left == 0:
                self._retry_tests[retry_test_id]["completed"] = True
            return next_instruction

    def list_retry_tests(self):
        with self._retry_tests_lock:
            return [
                self.__to_serializeable_retry_test(x)
                for x in self._retry_tests.values()
            ]

    def delete_retry_test(self, retry_test_id):
        with self._retry_tests_lock:
            self.get_retry_test(retry_test_id)
            del self._retry_tests[retry_test_id]
