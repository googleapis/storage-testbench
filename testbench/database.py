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
import copy
import datetime
import json
import os
import pathlib
import threading
import uuid
from typing import Any, Callable, TypeVar

import gcs
import testbench

T = TypeVar("T")


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
        soft_deleted_objects,
    ):
        self._resources_lock = threading.RLock()
        self._buckets = buckets
        self._objects = objects
        self._live_generations = live_generations
        self._soft_deleted_objects = soft_deleted_objects

        self._uploads_lock = threading.RLock()
        self._uploads = uploads

        self._rewrites_lock = threading.RLock()
        self._rewrites = rewrites

        self._retry_tests_lock = threading.RLock()
        self._retry_tests = retry_tests
        self._supported_methods = supported_methods

        self._projects_lock = threading.RLock()
        self._projects = {}

    @classmethod
    def init(cls):
        return cls({}, {}, {}, {}, {}, {}, [], {})

    def clear(self):
        """Clear all data except for the supported method list."""
        with self._resources_lock:
            self._buckets = {}
            self._objects = {}
            self._live_generations = {}
            self._soft_deleted_objects = {}
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

    def __bucket_key(self, bucket_name, context):
        if context is not None:
            return bucket_name
        return testbench.common.bucket_name_to_proto(bucket_name)

    def get_bucket(self, bucket_name, context, preconditions=[]):
        with self._resources_lock:
            bucket = self._buckets.get(self.__bucket_key(bucket_name, context))
            if bucket is None:
                return testbench.error.notfound("Bucket %s" % bucket_name, context)
            for precondition in preconditions:
                if not precondition(bucket, context):
                    return None
            return bucket

    def insert_bucket(self, bucket, context):
        with self._resources_lock:
            if bucket.metadata.name in self._buckets:
                return testbench.error.already_exists(context)
            self._buckets[bucket.metadata.name] = bucket
            self._objects[bucket.metadata.name] = {}
            self._live_generations[bucket.metadata.name] = {}
            self._soft_deleted_objects[bucket.metadata.name] = {}

    def list_bucket(self, project_id, prefix, context):
        with self._resources_lock:
            if project_id is None or project_id.endswith("-"):
                testbench.error.invalid("Project id %s" % project_id, context)
            if not prefix:
                return self._buckets.values()

            prefix = "projects/_/buckets/" + prefix
            buckets = []
            for bucket in self._buckets.values():
                name = bucket.metadata.name
                if name.find(prefix) == 0:
                    buckets.append(bucket)

            return buckets

    def delete_bucket(self, bucket_name, context, preconditions=[]):
        with self._resources_lock:
            bucket = self.get_bucket(bucket_name, context, preconditions)
            if len(self._live_generations[bucket.metadata.name]) > 0:
                testbench.error.invalid(
                    "Deleting non-empty bucket %s %s"
                    % (
                        bucket.metadata.name,
                        self._live_generations[bucket.metadata.name],
                    ),
                    context,
                )
            del self._buckets[bucket.metadata.name]
            del self._objects[bucket.metadata.name]
            del self._live_generations[bucket.metadata.name]
            del self._soft_deleted_objects[bucket.metadata.name]

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
                self.insert_bucket(bucket_test, None)
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
            request.match_glob,
            request.soft_deleted,
        )

    @classmethod
    def __extract_list_object_request(cls, request, context):
        if context is not None:
            return cls.__extract_list_object_request_grpc(request)
        delimiter = request.args.get("delimiter", "")
        prefix = request.args.get("prefix", "")
        versions = request.args.get("versions", False, type=bool)
        start_offset = request.args.get("startOffset", "")
        end_offset = request.args.get("endOffset")
        include_trailing_delimiter = request.args.get("includeTrailingDelimiter", False)
        match_glob = request.args.get("matchGlob", None)
        soft_deleted = request.args.get("softDeleted", False)
        return (
            delimiter,
            prefix,
            versions,
            start_offset,
            end_offset,
            include_trailing_delimiter,
            match_glob,
            soft_deleted,
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

    def __soft_delete_object(
        self, bucket_name, object_name, blob, retention_duration, context
    ):
        bucket_key = self.__bucket_key(bucket_name, context)
        if self._soft_deleted_objects[bucket_key].get(object_name) is None:
            self._soft_deleted_objects[bucket_key][object_name] = []
        soft_delete_time = datetime.datetime.now(datetime.timezone.utc)
        hard_delete_time = soft_delete_time + datetime.timedelta(0, retention_duration)
        blob.metadata.soft_delete_time.FromDatetime(soft_delete_time)
        blob.metadata.hard_delete_time.FromDatetime(hard_delete_time)
        self._soft_deleted_objects[bucket_key][object_name].append(blob)

    def __remove_expired_objects_from_soft_delete(
        self, bucket_name, object_name, context
    ):
        bucket_key = self.__bucket_key(bucket_name, context)
        now = datetime.datetime.now()

        if self._soft_deleted_objects[bucket_key].get(object_name) is not None:
            self._soft_deleted_objects[bucket_key][object_name] = list(
                filter(
                    lambda blob: now < blob.metadata.hard_delete_time.ToDatetime(),
                    self._soft_deleted_objects[bucket_key][object_name],
                )
            )

    def __remove_restored_soft_deleted_object(
        self, bucket_name, object_name, generation, context
    ):
        bucket_key = self.__bucket_key(bucket_name, context)
        if self._soft_deleted_objects[bucket_key].get(object_name) is not None:
            self._soft_deleted_objects[bucket_key][object_name] = list(
                filter(
                    lambda blob: blob.metadata.generation == generation,
                    self._soft_deleted_objects[bucket_key][object_name],
                )
            )

    def __get_soft_deleted_object(self, bucket_name, object_name, generation, context):
        bucket_key = self.__bucket_key(bucket_name, context)
        blobs = self._soft_deleted_objects[bucket_key].get(object_name, [])
        blob = next(
            (blob for blob in blobs if blob.metadata.generation == generation), None
        )
        if blob is None:
            return testbench.error.notfound(object_name, context)
        return blob

    def __get_all_soft_deleted_objects(self, bucket_name, context):
        bucket_key = self.__bucket_key(bucket_name, context)
        all_soft_deleted = []
        for soft_deleted_list in self._soft_deleted_objects[bucket_key].values():
            all_soft_deleted.extend(soft_deleted_list)
        all_soft_deleted.sort(key=lambda blob: blob.metadata.generation)
        return all_soft_deleted

    def list_object(self, request, bucket_name, context):
        with self._resources_lock:
            bucket = self.__get_bucket_for_object(bucket_name, context)
            bucket_with_metadata = self.get_bucket(bucket_name, context)
            (
                delimiter,
                prefix,
                versions,
                start_offset,
                end_offset,
                include_trailing_delimiter,
                match_glob,
                soft_deleted,
            ) = self.__extract_list_object_request(request, context)
            items = []
            prefixes = set()

            if (
                soft_deleted
                and not bucket_with_metadata.metadata.HasField("soft_delete_policy")
            ) or (soft_deleted and versions):
                return testbench.error.invalid("bad request", context)

            objects = bucket.values()
            if soft_deleted:
                objects = self.__get_all_soft_deleted_objects(bucket_name, context)

            for obj in objects:
                generation = obj.metadata.generation
                name = obj.metadata.name
                if (
                    not soft_deleted
                    and not versions
                    and generation
                    != self.__get_live_generation(bucket_name, name, context)
                ):
                    continue
                if name.find(prefix) != 0:
                    continue
                if name < start_offset:
                    continue
                if end_offset and name >= end_offset:
                    continue
                if match_glob and not pathlib.PurePath(name).match(match_glob):
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

    def __get_object(
        self,
        bucket_name,
        object_name,
        context=None,
        generation=None,
        preconditions=[],
        require_live_current_generation=True,
    ):
        bucket_key = self.__bucket_key(bucket_name, context)
        if bucket_key not in self._live_generations:
            return testbench.error.notfound("Bucket %s" % bucket_name, context)

        live_generation = self._live_generations[bucket_key].get(object_name, None)

        if generation is None or int(generation) == 0:
            # We are looking for the latest "live" version, but there is none.
            if live_generation is None:
                if require_live_current_generation:
                    return testbench.error.notfound(
                        "Live version of object %s/%s" % (bucket_name, object_name),
                        context,
                    )
                return None, None
            lookup_generation = int(live_generation)
        else:
            lookup_generation = int(generation)
        bucket = self.__get_bucket_for_object(bucket_name, context)
        blob = bucket.get("%s#%d" % (object_name, lookup_generation), None)
        if blob is None:
            return testbench.error.notfound(
                "Could not find object %s/%s#%d"
                % (bucket_name, object_name, lookup_generation),
                context,
            )
        for precondition in preconditions:
            if not precondition(blob, live_generation, context):
                return None, None
        return blob, live_generation

    def get_object(
        self,
        bucket_name,
        object_name,
        context=None,
        generation=None,
        preconditions=[],
        soft_deleted=False,
    ):
        with self._resources_lock:
            blob = None
            if not soft_deleted:
                blob, _ = self.__get_object(
                    bucket_name, object_name, context, generation, preconditions
                )
            else:
                bucket_with_metadata = self.get_bucket(bucket_name, context)
                if not bucket_with_metadata.metadata.HasField("soft_delete_policy"):
                    testbench.error.invalid("SoftDeletePolicyRequired", context)
                blob = self.__get_soft_deleted_object(
                    bucket_name, object_name, int(generation), context
                )
            # return a snapshot copy of the blob/blob.metadata
            if blob is None:
                return None
            b = copy.copy(blob)
            b.metadata = copy.copy(blob.metadata)
            return b

    def insert_object(self, bucket_name, blob, context=None, preconditions=[]):
        with self._resources_lock:
            object_name = blob.metadata.name
            bucket = self.__get_bucket_for_object(bucket_name, context)
            assert bucket is not None  # raises otherwise

            live_generation = self.__get_live_generation(
                bucket_name, object_name, context
            )
            if live_generation is not None:
                current = bucket.get("%s#%d" % (object_name, live_generation))
            else:
                current = None
            # Validate the preconditions against the existing object, if any
            for precondition in preconditions:
                if not precondition(current, live_generation, context):
                    return

            # generations are initialized based on time in gcs.object.Object, so this is
            # assumed to be higher than existing generations.
            generation = blob.metadata.generation
            bucket["%s#%d" % (object_name, generation)] = blob
            self.__set_live_generation(bucket_name, object_name, generation, context)

    def delete_object(
        self,
        bucket_name: str,
        object_name: str,
        context=None,
        generation: int = 0,
        preconditions=[],
    ):
        with self._resources_lock:
            blob, live_generation = self.__get_object(
                bucket_name, object_name, context, generation, preconditions
            )
            # _get_object() raises if the object is not found or the generation mismatches.
            # There are only two cases:
            if generation == 0 or live_generation == generation:
                self.__del_live_generation(bucket_name, object_name, context)
            bucket = self.__get_bucket_for_object(bucket_name, context)
            bucket_with_metadata = self.get_bucket(bucket_name, context)
            if bucket_with_metadata.metadata.HasField("soft_delete_policy"):
                self.__soft_delete_object(
                    bucket_name,
                    object_name,
                    blob,
                    bucket_with_metadata.metadata.soft_delete_policy.retention_duration.seconds,
                    context,
                )
            bucket.pop("%s#%d" % (blob.metadata.name, blob.metadata.generation), None)

    def do_update_object(
        self,
        bucket_name: str,
        object_name: str,
        *,
        update_fn: Callable[[Any, Any], T],
        context=None,
        generation=None,
        preconditions=[],
        require_live_current_generation=True,
    ) -> T:
        with self._resources_lock:
            blob, live_generation = self.__get_object(
                bucket_name,
                object_name,
                context,
                generation,
                preconditions,
                require_live_current_generation=require_live_current_generation,
            )
            return update_fn(blob, live_generation)

    def restore_object(
        self,
        bucket_name: str,
        object_name: str,
        generation: int,
        preconditions=[],
        context=None,
    ) -> T:
        with self._resources_lock:
            bucket_with_metadata = self.get_bucket(bucket_name, context)
            if not bucket_with_metadata.metadata.HasField("soft_delete_policy"):
                testbench.error.invalid("SoftDeletePolicyRequired", context)
            bucket = self.__get_bucket_for_object(bucket_name, context)
            blob = bucket.get("%s#%d" % (object_name, generation), None)
            if blob is not None:
                testbench.error.not_soft_deleted(context)

            self.__remove_expired_objects_from_soft_delete(
                bucket_name,
                object_name,
                context,
            )
            blob = self.__get_soft_deleted_object(
                bucket_name, object_name, generation, context
            )
            if blob is not None:
                blob.metadata.create_time.FromDatetime(
                    datetime.datetime.now(datetime.timezone.utc)
                )
                blob.metadata.ClearField("soft_delete_time")
                blob.metadata.metageneration = 1
                blob.metadata.generation = blob.metadata.generation + 1
                if bucket_with_metadata.metadata.autoclass.enabled is True:
                    blob.metadata.storage_class = "STANDARD"
                self.insert_object(bucket_name, blob, context, preconditions)
                self.__remove_restored_soft_deleted_object(
                    bucket_name, object_name, generation, context
                )

            return blob

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
            upload = self.get_upload(upload_id, context)
            if upload is not None:
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

    # ==== PROJECTS ==== #

    def get_project(self, project_id):
        """Find a project and return the GcsProject object."""
        # Dynamically create the projects. The GCS testbench does not have functions
        # to create projects, nor do we want to create such functions. The point is
        # to test the GCS client library, not the IAM client library.
        with self._projects_lock:
            return self._projects.setdefault(
                project_id, gcs.project.GcsProject(project_id)
            )

    # ==== RETRY_TESTS ==== #

    @classmethod
    def __to_serializeable_retry_test(cls, retry_test):
        return {
            "id": retry_test["id"],
            "instructions": {
                key: list(value) for key, value in retry_test["instructions"].items()
            },
            "completed": retry_test["completed"],
            "transport": retry_test["transport"].upper(),
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
            testbench.common.retry_return_broken_stream_after_bytes,
            testbench.common.retry_stall_after_bytes,
            testbench.common.retry_return_redirection_token,
            testbench.common.retry_return_handle_and_redirection_token,
            testbench.common.retry_expect_redirection_token,
        ]:
            if expr.match(failure) is not None:
                return
        testbench.error.invalid("The fault injection request <%s>" % failure, None)

    def __validate_grpc_method_implemented_retry(self, method):
        """Returns Unimplemented 501 for methods that are not yet supported.
        Temporary validation while adding Retry Test API support in gRPC."""
        not_supported_grpc_w_retry = {
            "storage.bucket_acl.get",
            "storage.bucket_acl.list",
            "storage.bucket_acl.delete",
            "storage.bucket_acl.insert",
            "storage.bucket_acl.patch",
            "storage.bucket_acl.update",
            "storage.default_object_acl.get",
            "storage.default_object_acl.list",
            "storage.default_object_acl.delete",
            "storage.default_object_acl.insert",
            "storage.default_object_acl.patch",
            "storage.default_object_acl.update",
            "storage.hmacKey.create",
            "storage.hmacKey.delete",
            "storage.hmacKey.get",
            "storage.hmacKey.list",
            "storage.hmacKey.update",
            "storage.object_acl.get",
            "storage.object_acl.list",
            "storage.object_acl.delete",
            "storage.object_acl.insert",
            "storage.object_acl.patch",
            "storage.object_acl.update",
            "storage.notifications.delete",
            "storage.notifications.get",
            "storage.notifications.insert",
            "storage.notifications.list",
            "storage.serviceaccount.get",
        }
        if method in not_supported_grpc_w_retry:
            testbench.error.unimplemented(
                "Retry Test API not supported for the requested method <%s> in GRPC"
                % method,
                None,
            )

    def __validate_instructions(self, instructions, transport="HTTP"):
        for method, failures in instructions.items():
            if method not in self._supported_methods:
                testbench.error.invalid(
                    "The requested method <%s> for fault injection" % method, None
                )
            # TODO: Temporary validation will be removed once Retry Test API is fully supported in gRPC.
            if transport.upper() == "GRPC":
                self.__validate_grpc_method_implemented_retry(method)
            for failure in failures:
                self.__validate_injected_failure_description(failure)

    def __validate_transport(self, transport):
        if transport.upper() not in ("HTTP", "GRPC"):
            testbench.error.invalid(
                "The requested transport <%s> is not supported in the testbench"
                % transport,
                None,
            )

    def insert_retry_test(self, instructions, transport="HTTP"):
        with self._retry_tests_lock:
            # Validate transport - Invalid request for any value other than "HTTP" or "GRPC".
            self.__validate_transport(transport)
            self.__validate_instructions(instructions, transport)
            retry_test_id = uuid.uuid4().hex
            self._retry_tests[retry_test_id] = {
                "id": retry_test_id,
                "instructions": {
                    key: collections.deque(value) for key, value in instructions.items()
                },
                "completed": False,
                "transport": transport.upper(),
            }
            return self.__to_serializeable_retry_test(self._retry_tests[retry_test_id])

    def has_instructions_retry_test(self, retry_test_id, method, transport="HTTP"):
        with self._retry_tests_lock:
            retry_test = self.get_retry_test(retry_test_id)
            # Add validation for request transport as well.
            if (len(retry_test["instructions"].get(method, [])) > 0) and retry_test[
                "transport"
            ].upper() == transport.upper():
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
