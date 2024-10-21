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

import argparse
import datetime
import json
import logging
import time

import flask
from google.protobuf import json_format
from werkzeug import serving
from werkzeug.middleware.dispatcher import DispatcherMiddleware

import gcs as gcs_type
import testbench
from google.storage.v2 import storage_pb2
from testbench.servers import echo, iam_rest_server, projects_rest_server

db = testbench.database.Database.init()
# retry_test decorates a routing function to handle the Retry Test API, with
# method names based on the JSON API
retry_test = testbench.common.gen_retry_test_decorator(db)
grpc_port = 0
grpc_service = None


# === DEFAULT ENTRY FOR REST SERVER === #
root = flask.Flask(__name__)
root.debug = False
root.register_error_handler(Exception, testbench.error.RestException.handler)


@root.route("/")
def index():
    return "OK"


@root.route("/raise_error")
def raise_error():
    etype = flask.request.args.get("etype")
    msg = flask.request.args.get("msg", "")
    if etype is not None:
        raise TypeError(msg)
    else:
        raise Exception(msg)


def xml_put_object(bucket_name, object_name):
    db.insert_test_bucket()
    bucket = db.get_bucket(bucket_name, None).metadata
    blob, fake_request = gcs_type.object.Object.init_xml(
        flask.request, bucket, object_name
    )
    db.insert_object(
        bucket_name,
        blob,
        context=None,
        preconditions=testbench.common.make_xml_preconditions(flask.request),
    )
    response = flask.make_response("")
    response.headers["x-goog-hash"] = fake_request.headers.get("x-goog-hash")
    return response


def xml_get_object(bucket_name, object_name):
    fake_request = testbench.common.FakeRequest.init_xml(flask.request)
    blob = db.get_object(
        bucket_name,
        object_name,
        generation=flask.request.args.get("generation"),
        preconditions=testbench.common.make_xml_preconditions(flask.request),
        context=None,
    )
    response = blob.rest_media(fake_request)
    response.headers["x-goog-stored-content-length"] = len(blob.media)
    encoding = blob.metadata.content_encoding
    response.headers["x-goog-stored-content-encoding"] = (
        "identity" if encoding is None or encoding == "" else encoding
    )
    return response


@root.route("/<path:object_name>", subdomain="<bucket_name>")
@retry_test(method="storage.objects.get")
def root_get_object(bucket_name, object_name):
    return xml_get_object(bucket_name, object_name)


@root.route("/<bucket_name>/<path:object_name>", subdomain="")
@retry_test(method="storage.objects.get")
def root_get_object_with_bucket(bucket_name, object_name):
    return xml_get_object(bucket_name, object_name)


@root.route("/<path:object_name>", subdomain="<bucket_name>", methods=["PUT"])
@retry_test(method="storage.objects.insert")
def root_put_object(bucket_name, object_name):
    return xml_put_object(bucket_name, object_name)


@root.route("/<bucket_name>/<path:object_name>", methods=["POST"])
@retry_test(method="storage.objects.insert")
def root_create_resumable_object(bucket_name, object_name):
    # TODO: add resumable XML API support. Only needed to cause failures
    # using RetryTestAPI.
    testbench.error.generic("Not implemented", 501, None, None)


@root.route("/<bucket_name>/<path:object_name>", subdomain="", methods=["PUT"])
@retry_test(method="storage.objects.insert")
def root_put_object_with_bucket(bucket_name, object_name):
    return xml_put_object(bucket_name, object_name)


@root.route("/retry_tests", methods=["GET"])
def list_retry_tests():
    response = json.dumps({"retry_test": db.list_retry_tests()})
    return flask.Response(response, status=200, content_type="application/json")


@root.route("/retry_test", methods=["POST"])
def create_retry_test():
    payload = json.loads(flask.request.data)
    test_instruction_set = payload.get("instructions", None)
    if not test_instruction_set:
        return flask.Response(
            "instructions is not defined", status=400, content_type="text/plain"
        )
    # Backfill a newly added field "transport" in the retry test resource.
    transport = payload.get("transport", "HTTP")
    retry_test = db.insert_retry_test(test_instruction_set, transport)
    retry_test_response = json.dumps(retry_test)
    return flask.Response(
        retry_test_response, status=200, content_type="application/json"
    )


@root.route("/retry_test/<test_id>", methods=["GET"])
def get_retry_test(test_id):
    retry_test = json.dumps(db.get_retry_test(test_id))
    return flask.Response(retry_test, status=200, content_type="application/json")


@root.route("/retry_test/<test_id>", methods=["DELETE"])
def delete_retry_test(test_id):
    db.delete_retry_test(test_id)
    return flask.Response("Deleted {}".format(test_id), 200, content_type="text/plain")


@root.route("/start_grpc")
def start_grpc():
    # We need to do this because `gunicorn` will spawn a new subprocess ( a worker )
    # when running `Flask` server. If we start `gRPC` server before the spawn of
    # the subprocess, it's nearly impossible to share the `database` with the new
    # subprocess because Python will copy everything in the memory from the parent
    # process to the subprocess ( So we have 2 separate instance of `database` ).
    # The endpoint will start the `gRPC` server in the same subprocess so there is
    # only one instance of `database`.
    global grpc_port
    global grpc_service
    global db
    if grpc_port == 0:
        port = flask.request.args.get("port", "0")
        echo_metadata = flask.request.args.get("echo-metadata", False)
        grpc_port, grpc_service = testbench.grpc_server.run(
            int(port), db, echo_metadata=echo_metadata
        )
    return str(grpc_port)


# === WSGI APP TO HANDLE JSON API === #
GCS_HANDLER_PATH = "/storage/v1"
gcs = flask.Flask(__name__)
gcs.debug = False
gcs.register_error_handler(Exception, testbench.error.RestException.handler)


@gcs.before_request
def handle_gzip_compressed_request():
    return testbench.common.handle_gzip_request(flask.request)


# === BUCKET === #


@gcs.route("/b", methods=["GET"])
@retry_test(method="storage.buckets.list")
def bucket_list():
    db.insert_test_bucket()
    project = flask.request.args.get("project")
    projection = flask.request.args.get("projection", "noAcl")
    fields = flask.request.args.get("fields", None)
    prefix = flask.request.args.get("prefix", "")
    response = {
        "kind": "storage#buckets",
        "items": [bucket.rest() for bucket in db.list_bucket(project, prefix, None)],
    }
    return testbench.common.filter_response_rest(response, projection, fields)


@gcs.route("/b", methods=["POST"])
@retry_test(method="storage.buckets.insert")
def bucket_insert():
    db.insert_test_bucket()
    bucket, projection = gcs_type.bucket.Bucket.init(flask.request, None)
    fields = flask.request.args.get("fields", None)
    db.insert_bucket(bucket, None)
    return testbench.common.filter_response_rest(bucket.rest(), projection, fields)


@gcs.route("/b/<bucket_name>")
@retry_test(method="storage.buckets.get")
def bucket_get(bucket_name):
    db.insert_test_bucket()
    db.insert_test_bucket()
    bucket = db.get_bucket(
        bucket_name,
        None,
        preconditions=testbench.common.make_json_bucket_preconditions(flask.request),
    )
    projection = testbench.common.extract_projection(flask.request, "noAcl", None)
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(bucket.rest(), projection, fields)


@gcs.route("/b/<bucket_name>", methods=["PUT"])
@retry_test(method="storage.buckets.update")
def bucket_update(bucket_name):
    db.insert_test_bucket()
    bucket = db.get_bucket(
        bucket_name,
        None,
        preconditions=testbench.common.make_json_bucket_preconditions(flask.request),
    )
    bucket.update(flask.request, None)
    projection = testbench.common.extract_projection(flask.request, "full", None)
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(bucket.rest(), projection, fields)


@gcs.route("/b/<bucket_name>", methods=["PATCH", "POST"])
@retry_test(method="storage.buckets.patch")
def bucket_patch(bucket_name):
    testbench.common.enforce_patch_override(flask.request)
    bucket = db.get_bucket(
        bucket_name,
        None,
        preconditions=testbench.common.make_json_bucket_preconditions(flask.request),
    )
    bucket.patch(flask.request, None)
    projection = testbench.common.extract_projection(flask.request, "full", None)
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(bucket.rest(), projection, fields)


@gcs.route("/b/<bucket_name>", methods=["DELETE"])
@retry_test(method="storage.buckets.delete")
def bucket_delete(bucket_name):
    db.delete_bucket(
        bucket_name,
        None,
        preconditions=testbench.common.make_json_bucket_preconditions(flask.request),
    )
    return ""


# === BUCKET ACL === #


@gcs.route("/b/<bucket_name>/acl")
@retry_test(method="storage.bucket_acl.list")
def bucket_acl_list(bucket_name):
    bucket = db.get_bucket(bucket_name, None)
    response = {
        "kind": "storage#bucketAccessControls",
        "items": [
            testbench.proto2rest.bucket_access_control_as_rest(bucket_name, acl)
            for acl in bucket.metadata.acl
        ],
    }
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl", methods=["POST"])
@retry_test(method="storage.bucket_acl.insert")
def bucket_acl_insert(bucket_name):
    bucket = db.get_bucket(bucket_name, None)
    acl = bucket.insert_acl(flask.request, None)
    response = testbench.proto2rest.bucket_access_control_as_rest(bucket_name, acl)
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl/<entity>")
@retry_test(method="storage.bucket_acl.get")
def bucket_acl_get(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, None)
    acl = bucket.get_acl(entity, None)
    response = testbench.proto2rest.bucket_access_control_as_rest(bucket_name, acl)
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PUT"])
@retry_test(method="storage.bucket_acl.update")
def bucket_acl_update(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, None)
    acl = bucket.update_acl(flask.request, entity, None)
    response = testbench.proto2rest.bucket_access_control_as_rest(bucket_name, acl)
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PATCH", "POST"])
@retry_test(method="storage.bucket_acl.patch")
def bucket_acl_patch(bucket_name, entity):
    testbench.common.enforce_patch_override(flask.request)
    bucket = db.get_bucket(bucket_name, None)
    acl = bucket.patch_acl(flask.request, entity, None)
    response = testbench.proto2rest.bucket_access_control_as_rest(bucket_name, acl)
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["DELETE"])
@retry_test(method="storage.bucket_acl.delete")
def bucket_acl_delete(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, None)
    bucket.delete_acl(entity, None)
    return flask.make_response("")


@gcs.route("/b/<bucket_name>/defaultObjectAcl")
@retry_test(method="storage.default_object_acl.list")
def bucket_default_object_acl_list(bucket_name):
    bucket = db.get_bucket(bucket_name, None)
    response = {
        "kind": "storage#objectAccessControls",
        "items": [
            testbench.proto2rest.default_object_access_control_as_rest(bucket_name, acl)
            for acl in bucket.metadata.default_object_acl
        ],
    }
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/defaultObjectAcl", methods=["POST"])
@retry_test(method="storage.default_object_acl.insert")
def bucket_default_object_acl_insert(bucket_name):
    bucket = db.get_bucket(bucket_name, None)
    acl = bucket.insert_default_object_acl(flask.request, None)
    response = testbench.proto2rest.default_object_access_control_as_rest(
        bucket_name, acl
    )
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>")
@retry_test(method="storage.default_object_acl.get")
def bucket_default_object_acl_get(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, None)
    acl = bucket.get_default_object_acl(entity, None)
    response = testbench.proto2rest.default_object_access_control_as_rest(
        bucket_name, acl
    )
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PUT"])
@retry_test(method="storage.default_object_acl.update")
def bucket_default_object_acl_update(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, None)
    acl = bucket.update_default_object_acl(flask.request, entity, None)
    response = testbench.proto2rest.default_object_access_control_as_rest(
        bucket_name, acl
    )
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PATCH", "POST"])
@retry_test(method="storage.default_object_acl.patch")
def bucket_default_object_acl_patch(bucket_name, entity):
    testbench.common.enforce_patch_override(flask.request)
    bucket = db.get_bucket(bucket_name, None)
    acl = bucket.patch_default_object_acl(flask.request, entity, None)
    response = testbench.proto2rest.default_object_access_control_as_rest(
        bucket_name, acl
    )
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["DELETE"])
@retry_test(method="storage.default_object_acl.delete")
def bucket_default_object_acl_delete(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, None)
    bucket.delete_default_object_acl(entity, None)
    return flask.make_response("")


@gcs.route("/b/<bucket_name>/notificationConfigs")
@retry_test(method="storage.notifications.list")
def bucket_notification_list(bucket_name):
    bucket = db.get_bucket(bucket_name, None)
    return bucket.list_notifications(None)


@gcs.route("/b/<bucket_name>/notificationConfigs", methods=["POST"])
@retry_test(method="storage.notifications.insert")
def bucket_notification_insert(bucket_name):
    bucket = db.get_bucket(bucket_name, None)
    return bucket.insert_notification(flask.request.data, None)


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>")
@retry_test(method="storage.notifications.get")
def bucket_notification_get(bucket_name, notification_id):
    bucket = db.get_bucket(bucket_name, None)
    return bucket.get_notification(notification_id, None)


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>", methods=["DELETE"])
@retry_test(method="storage.notifications.delete")
def bucket_notification_delete(bucket_name, notification_id):
    bucket = db.get_bucket(bucket_name, None)
    bucket.delete_notification(notification_id, None)
    return ""


@gcs.route("/b/<bucket_name>/iam")
@retry_test(method="storage.buckets.getIamPolicy")
def bucket_get_iam_policy(bucket_name):
    db.insert_test_bucket()
    bucket = db.get_bucket(bucket_name, None)
    response = json_format.MessageToDict(bucket.iam_policy)
    response["kind"] = "storage#policy"
    return response


@gcs.route("/b/<bucket_name>/iam", methods=["PUT"])
@retry_test(method="storage.buckets.setIamPolicy")
def bucket_set_iam_policy(bucket_name):
    db.insert_test_bucket()
    bucket = db.get_bucket(bucket_name, None)
    bucket.set_iam_policy(flask.request, None)
    response = json_format.MessageToDict(bucket.iam_policy)
    response["kind"] = "storage#policy"
    return response


@gcs.route("/b/<bucket_name>/iam/testPermissions")
@retry_test(method="storage.buckets.testIamPermissions")
def bucket_test_iam_permissions(bucket_name):
    db.get_bucket(bucket_name, None)
    permissions = flask.request.args.getlist("permissions")
    result = {"kind": "storage#testIamPermissionsResponse", "permissions": permissions}
    return result


@gcs.route("/b/<bucket_name>/lockRetentionPolicy", methods=["POST"])
@retry_test(method="storage.buckets.lockRetentionPolicy")
def bucket_lock_retention_policy(bucket_name):
    bucket = db.get_bucket(
        bucket_name,
        context=None,
        preconditions=testbench.common.make_json_bucket_preconditions(flask.request),
    )
    bucket.metadata.retention_policy.is_locked = True
    bucket.metadata.retention_policy.effective_time.FromDatetime(
        datetime.datetime.now()
    )
    return bucket.rest()


# === OBJECT === #


@gcs.route("/b/<bucket_name>/o")
@retry_test(method="storage.objects.list")
def object_list(bucket_name):
    db.insert_test_bucket()
    items, prefixes = db.list_object(flask.request, bucket_name, None)
    response = {
        "kind": "storage#objects",
        "items": [gcs_type.object.Object.rest(blob) for blob in items],
        "prefixes": prefixes,
    }
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/o/<path:object_name>", methods=["PUT"])
@retry_test(method="storage.objects.update")
def object_update(bucket_name, object_name):
    projection = testbench.common.extract_projection(flask.request, "full", None)
    fields = flask.request.args.get("fields", None)

    def update_impl(blob, live_generation):
        del live_generation
        blob.update(flask.request, None)
        return testbench.common.filter_response_rest(
            blob.rest_metadata(), projection, fields
        )

    return db.do_update_object(
        bucket_name,
        object_name,
        generation=flask.request.args.get("generation", None),
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
        update_fn=update_impl,
    )


@gcs.route("/b/<bucket_name>/o/<path:object_name>", methods=["PATCH", "POST"])
@retry_test(method="storage.objects.patch")
def object_patch(bucket_name, object_name):
    testbench.common.enforce_patch_override(flask.request)
    projection = testbench.common.extract_projection(flask.request, "full", None)
    fields = flask.request.args.get("fields", None)

    def patch_impl(blob, live_generation):
        del live_generation
        blob.patch(flask.request, None)
        return testbench.common.filter_response_rest(
            blob.rest_metadata(), projection, fields
        )

    return db.do_update_object(
        bucket_name,
        object_name,
        generation=flask.request.args.get("generation", None),
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
        update_fn=patch_impl,
    )


@gcs.route("/b/<bucket_name>/o/<path:object_name>", methods=["DELETE"])
@retry_test(method="storage.objects.delete")
def object_delete(bucket_name, object_name):
    db.delete_object(
        bucket_name,
        object_name,
        generation=int(flask.request.args.get("generation", 0)),
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
    )
    return ""


@gcs.route("/b/<bucket_name>/o/<path:object_name>")
@retry_test(method="storage.objects.get")
def object_get(bucket_name, object_name):
    soft_deleted = flask.request.args.get("softDeleted", False, bool)
    media = flask.request.args.get("alt", None)
    generation = flask.request.args.get("generation", None)
    if (soft_deleted and generation is None) or (soft_deleted and media == "media"):
        return testbench.error.invalid("invalid request", None)

    blob = db.get_object(
        bucket_name,
        object_name,
        generation=generation,
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
        soft_deleted=soft_deleted,
    )
    if media is None or media == "json":
        projection = testbench.common.extract_projection(flask.request, "noAcl", None)
        fields = flask.request.args.get("fields", None)
        return testbench.common.filter_response_rest(
            blob.rest_metadata(), projection, fields
        )
    if media != "media":
        testbench.error.invalid("Alt %s")
    testbench.csek.validation(
        flask.request, blob.metadata.customer_encryption.key_sha256_bytes, False, None
    )
    return blob.rest_media(flask.request)


# === OBJECT SPECIAL OPERATIONS === #


@gcs.route("/b/<bucket_name>/o/<path:object_name>/compose", methods=["POST"])
@retry_test(method="storage.objects.compose")
def objects_compose(bucket_name, object_name):
    bucket = db.get_bucket(bucket_name, None).metadata
    payload = json.loads(flask.request.data)
    source_objects = payload.get("sourceObjects", None)
    if source_objects is None:
        testbench.error.missing("source component", None)
    if len(source_objects) > 32:
        testbench.error.invalid(
            "The number of source components provided (%d > 32)" % len(source_objects),
            None,
        )
    composed_media = b""
    for source_object in source_objects:
        source_object_name = source_object.get("name")
        if source_object_name is None:
            testbench.error.missing("Name of source compose object", None)
        generation = source_object.get("generation", None)
        if_generation_match = None
        preconditions = source_object.get("objectPreconditions", None)
        if preconditions is not None:
            if_generation_match = preconditions.get("ifGenerationMatch", None)

        def precondition(_, live_version, ctx):
            if if_generation_match is None or int(if_generation_match) == live_version:
                return True
            return testbench.error.mismatch(
                "compose.ifGenerationMatch",
                expect=if_generation_match,
                actual=live_version,
                context=ctx,
            )

        source_object = db.get_object(
            bucket_name,
            source_object_name,
            generation=generation,
            preconditions=[precondition],
            context=None,
        )
        composed_media += source_object.media
    metadata = {"name": object_name, "bucket": bucket_name}
    metadata.update(payload.get("destination", {}))
    composed_object, _ = gcs_type.object.Object.init_dict(
        flask.request, metadata, composed_media, bucket, True
    )
    db.insert_object(
        bucket_name,
        composed_object,
        context=None,
        preconditions=testbench.common.make_json_preconditions(flask.request),
    )
    return composed_object.rest_metadata()


@gcs.route(
    "/b/<src_bucket_name>/o/<path:src_object_name>/copyTo/b/<dst_bucket_name>/o/<path:dst_object_name>",
    methods=["POST"],
)
@retry_test(method="storage.objects.copy")
def objects_copy(src_bucket_name, src_object_name, dst_bucket_name, dst_object_name):
    db.insert_test_bucket()
    dst_bucket = db.get_bucket(dst_bucket_name, None).metadata
    src_object = db.get_object(
        src_bucket_name,
        src_object_name,
        generation=flask.request.args.get("sourceGeneration", None),
        preconditions=testbench.common.make_json_preconditions(
            flask.request, prefix="ifSource"
        ),
        context=None,
    )
    testbench.csek.validation(
        flask.request,
        src_object.metadata.customer_encryption.key_sha256_bytes,
        False,
        None,
    )
    dst_metadata = storage_pb2.Object()
    dst_metadata.CopyFrom(src_object.metadata)
    del dst_metadata.acl[:]
    dst_metadata.bucket = dst_bucket_name
    dst_metadata.name = dst_object_name
    dst_media = b""
    dst_media += src_object.media
    dst_object, _ = gcs_type.object.Object.init(
        flask.request, dst_metadata, dst_media, dst_bucket, True, None
    )
    db.insert_object(
        dst_bucket_name,
        dst_object,
        context=None,
        preconditions=testbench.common.make_json_preconditions(flask.request),
    )
    if flask.request.data:
        dst_object.patch(flask.request, None)
    dst_object.metadata.metageneration = 1
    dst_object.metadata.update_time.FromDatetime(
        dst_object.metadata.create_time.ToDatetime()
    )
    return dst_object.rest_metadata()


@gcs.route(
    "/b/<src_bucket_name>/o/<path:src_object_name>/rewriteTo/b/<dst_bucket_name>/o/<path:dst_object_name>",
    methods=["POST"],
)
@retry_test(method="storage.objects.rewrite")
def objects_rewrite(src_bucket_name, src_object_name, dst_bucket_name, dst_object_name):
    db.insert_test_bucket()
    token, rewrite = flask.request.args.get("rewriteToken"), None
    src_object = None
    if token is None:
        rewrite = gcs_type.rewrite.Rewrite.init_rest(
            flask.request,
            src_bucket_name,
            src_object_name,
            dst_bucket_name,
            dst_object_name,
        )
        db.insert_rewrite(rewrite)
    else:
        rewrite = db.get_rewrite(token, None)
    src_object = db.get_object(
        src_bucket_name,
        src_object_name,
        generation=rewrite.request.args.get("sourceGeneration", None),
        preconditions=testbench.common.make_json_preconditions(
            rewrite.request, prefix="ifSource"
        ),
        context=None,
    )
    testbench.csek.validation(
        rewrite.request,
        src_object.metadata.customer_encryption.key_sha256_bytes,
        True,
        None,
    )
    total_bytes_rewritten = len(rewrite.media)
    total_bytes_rewritten += min(
        rewrite.max_bytes_rewritten_per_call, len(src_object.media) - len(rewrite.media)
    )
    rewrite.media += src_object.media[len(rewrite.media) : total_bytes_rewritten]
    done, dst_object = total_bytes_rewritten == len(src_object.media), None
    response = {
        "kind": "storage#rewriteResponse",
        "totalBytesRewritten": str(len(rewrite.media)),
        "objectSize": str(len(src_object.media)),
        "done": done,
    }
    if done:
        dst_bucket = db.get_bucket(dst_bucket_name, None).metadata
        dst_metadata = storage_pb2.Object()
        dst_metadata.CopyFrom(src_object.metadata)
        dst_metadata.bucket = dst_bucket_name
        dst_metadata.name = dst_object_name
        dst_media = rewrite.media
        dst_object, _ = gcs_type.object.Object.init(
            flask.request, dst_metadata, dst_media, dst_bucket, True, None
        )
        db.insert_object(
            dst_bucket_name,
            dst_object,
            context=None,
            preconditions=testbench.common.make_json_preconditions(rewrite.request),
        )
        if flask.request.data:
            dst_object.patch(rewrite.request, None)
        dst_object.metadata.metageneration = 1
        dst_object.metadata.update_time.FromDatetime(
            dst_object.metadata.create_time.ToDatetime()
        )
        resources = dst_object.rest_metadata()
        response["resource"] = resources
    else:
        response["rewriteToken"] = rewrite.token
    return response


@gcs.route("/b/<bucket_name>/o/<path:object_name>/restore", methods=["POST"])
@retry_test(method="storage.objects.restore")
def object_restore(bucket_name, object_name):
    if flask.request.args.get("generation") is None:
        return testbench.error.invalid("generation", None)
    blob = db.restore_object(
        bucket_name,
        object_name,
        int(flask.request.args.get("generation")),
        testbench.common.make_json_preconditions(flask.request),
    )
    projection = testbench.common.extract_projection(flask.request, "noAcl", None)
    return testbench.common.filter_response_rest(blob.rest_metadata(), projection, None)


# === OBJECT ACCESS CONTROL === #


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl")
@retry_test(method="storage.object_acl.list")
def object_acl_list(bucket_name, object_name):
    blob = db.get_object(
        bucket_name,
        object_name,
        generation=flask.request.args.get("generation", None),
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
    )
    response = {
        "kind": "storage#objectAccessControls",
        "items": [
            testbench.proto2rest.object_access_control_as_rest(
                bucket_name, object_name, str(blob.metadata.generation), a
            )
            for a in blob.metadata.acl
        ],
    }
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl", methods=["POST"])
@retry_test(method="storage.object_acl.insert")
def object_acl_insert(bucket_name, object_name):
    fields = flask.request.args.get("fields", None)

    def update_impl(blob, live_generation):
        del live_generation
        acl = blob.insert_acl(flask.request, None)
        response = testbench.proto2rest.object_access_control_as_rest(
            bucket_name, object_name, str(blob.metadata.generation), acl
        )
        return testbench.common.filter_response_rest(response, None, fields)

    return db.do_update_object(
        bucket_name,
        object_name,
        generation=flask.request.args.get("generation", None),
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
        update_fn=update_impl,
    )


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl/<entity>")
@retry_test(method="storage.object_acl.get")
def object_acl_get(bucket_name, object_name, entity):
    blob = db.get_object(
        bucket_name,
        object_name,
        generation=flask.request.args.get("generation", None),
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
    )
    acl = blob.get_acl(entity, None)
    response = testbench.proto2rest.object_access_control_as_rest(
        bucket_name, object_name, str(blob.metadata.generation), acl
    )
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl/<entity>", methods=["PUT"])
@retry_test(method="storage.object_acl.update")
def object_acl_update(bucket_name, object_name, entity):
    fields = flask.request.args.get("fields", None)

    def update_impl(blob, live_generation):
        del live_generation
        acl = blob.update_acl(flask.request, entity, None)
        response = testbench.proto2rest.object_access_control_as_rest(
            bucket_name, object_name, str(blob.metadata.generation), acl
        )
        return testbench.common.filter_response_rest(response, None, fields)

    return db.do_update_object(
        bucket_name,
        object_name,
        generation=flask.request.args.get("generation", None),
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
        update_fn=update_impl,
    )


@gcs.route(
    "/b/<bucket_name>/o/<path:object_name>/acl/<entity>", methods=["PATCH", "POST"]
)
@retry_test(method="storage.object_acl.patch")
def object_acl_patch(bucket_name, object_name, entity):
    testbench.common.enforce_patch_override(flask.request)
    fields = flask.request.args.get("fields", None)

    def update_impl(blob, live_generation):
        del live_generation
        acl = blob.patch_acl(flask.request, entity, None)
        response = testbench.proto2rest.object_access_control_as_rest(
            bucket_name, object_name, str(blob.metadata.generation), acl
        )
        return testbench.common.filter_response_rest(response, None, fields)

    return db.do_update_object(
        bucket_name,
        object_name,
        generation=flask.request.args.get("generation", None),
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
        update_fn=update_impl,
    )


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl/<entity>", methods=["DELETE"])
@retry_test(method="storage.object_acl.delete")
def object_acl_delete(bucket_name, object_name, entity):
    def update_impl(blob, live_generation):
        blob.delete_acl(entity, None)

    db.do_update_object(
        bucket_name,
        object_name,
        generation=flask.request.args.get("generation", None),
        preconditions=testbench.common.make_json_preconditions(flask.request),
        context=None,
        update_fn=update_impl,
    )
    return flask.make_response("")


# Define the WSGI application to handle bucket requests.
DOWNLOAD_HANDLER_PATH = "/download/storage/v1"
download = flask.Flask(__name__)
download.debug = False
download.register_error_handler(Exception, testbench.error.RestException.handler)


@download.route("/b/<bucket_name>/o/<path:object_name>")
def download_object_get(bucket_name, object_name):
    return object_get(bucket_name, object_name)


# Define the WSGI application to handle bucket requests.
UPLOAD_HANDLER_PATH = "/upload/storage/v1"
upload = flask.Flask(__name__)
upload.debug = False
upload.register_error_handler(Exception, testbench.error.RestException.handler)


@upload.before_request
def handle_gzip_compressed_request():
    return testbench.common.handle_gzip_request(flask.request)


@upload.route("/b/<bucket_name>/o", methods=["POST"])
@retry_test(method="storage.objects.insert")
def object_insert(bucket_name):
    # GCS supports "POST" calls for uploading data with an upload_id
    request = flask.request
    upload_id = request.args.get("upload_id")
    if upload_id is not None:
        return resumable_upload_chunk(bucket_name)

    db.insert_test_bucket()
    bucket = db.get_bucket(bucket_name, None).metadata
    upload_type = request.args.get("uploadType")
    if upload_type is None:
        testbench.error.missing("uploadType", None)
    elif upload_type not in {"multipart", "media", "resumable"}:
        testbench.error.invalid("uploadType %s" % upload_type, None)
    if upload_type == "resumable":
        upload = gcs_type.upload.Upload.init_resumable_rest(flask.request, bucket)
        db.insert_upload(upload)
        response = flask.make_response("")
        response.headers["Location"] = upload.location
        return response
    blob, projection = None, ""
    if upload_type == "media":
        blob, projection = gcs_type.object.Object.init_media(flask.request, bucket)
    elif upload_type == "multipart":
        blob, projection = gcs_type.object.Object.init_multipart(flask.request, bucket)
        # Handle stall for full uploads.
        testbench.common.extract_instruction(request, context=None)
        (
            stall_time,
            after_bytes,
            test_id,
        ) = testbench.common.get_stall_uploads_after_bytes(db, request)
        if stall_time:
            if test_id:
                db.dequeue_next_instruction(test_id, "storage.objects.insert")
            time.sleep(stall_time)

    db.insert_object(
        bucket_name,
        blob,
        context=None,
        preconditions=testbench.common.make_json_preconditions(flask.request),
    )
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(
        blob.rest_metadata(), projection, fields
    )


# TODO(#27) - this function is waaay to long.
@upload.route("/b/<bucket_name>/o", methods=["PUT"])
@retry_test(method="storage.objects.insert")
def resumable_upload_chunk(bucket_name):
    request = flask.request
    upload_id = request.args.get("upload_id")
    if upload_id is None:
        testbench.error.missing("upload_id in resumable_upload_chunk", None)
    upload = db.get_upload(upload_id, None)
    if upload.complete:
        return gcs_type.object.Object.rest(upload.metadata)
    last_byte_persisted = 0 if len(upload.media) == 0 else (len(upload.media) - 1)
    upload.transfer.add(request.environ.get("HTTP_TRANSFER_ENCODING", ""))
    content_length = request.headers.get("content-length", None)
    data = testbench.common.extract_media(request)
    if content_length is not None and int(content_length) != len(data):
        # This cannot be unit tested because flask.Flask.test_client() always
        # sends a valid content-length header
        testbench.error.invalid("content-length header", None)
    content_range = request.headers.get("content-range")
    custom_header_value = request.headers.get("x-goog-emulator-custom-header")
    if content_range is not None:
        items = list(testbench.common.content_range_split.match(content_range).groups())
        # TODO(#27) - maybe this should be an assert()
        # Given the structure of the regular expression, these conditions are always true:
        #   assert(len(items) == 2 or content_range_split.match() is None)
        #   assert((items[0] != items[1]) or items[0] == '*')
        if len(items) != 2 or (items[0] == items[1] and items[0] != "*"):
            testbench.error.invalid("content-range header", None)
        # TODO(#27) - maybe this should be an assert()
        # We check if the upload is complete before we get here.
        #   assert(not upload.completed)
        if items[0] == "*":
            if items[1] != "*" and int(items[1]) == len(upload.media):
                upload.complete = True
                blob, _ = gcs_type.object.Object.init(
                    upload.request,
                    upload.metadata,
                    upload.media,
                    upload.bucket,
                    False,
                    None,
                )
                blob.metadata.metadata["x_emulator_transfer_encoding"] = ":".join(
                    upload.transfer
                )
                db.insert_object(
                    bucket_name,
                    blob,
                    context=None,
                    preconditions=testbench.common.make_json_preconditions(
                        upload.request
                    ),
                )
                projection = testbench.common.extract_projection(
                    upload.request, "noAcl", None
                )
                fields = upload.request.args.get("fields", None)
                return testbench.common.filter_response_rest(
                    blob.rest_metadata(), projection, fields
                )
            return upload.resumable_status_rest()
        # In addition to chunk_last_byte, we also need to inspect chunk_first_byte.
        chunk_first_byte, chunk_last_byte = [v for v in items[0].split("-")]
        x_upload_content_length = int(
            upload.request.headers.get("x-upload-content-length", 0)
        )
        if chunk_last_byte == "*":
            x_upload_content_length = (
                len(data) if not x_upload_content_length else x_upload_content_length
            )
            chunk_last_byte = (
                len(data) - 1
                if chunk_first_byte == "*"
                else int(chunk_first_byte) + len(data) - 1
            )
        else:
            chunk_last_byte = int(chunk_last_byte)
        total_object_size = (
            int(items[1]) if items[1] != "*" else x_upload_content_length
        )
        if (
            x_upload_content_length != 0
            and x_upload_content_length != total_object_size
        ):
            testbench.error.mismatch(
                "X-Upload-Content-Length",
                x_upload_content_length,
                total_object_size,
                None,
                rest_code=400,
            )
        ### Handle error-after-bytes instructions, either retry test or x-goog-emulator-instructions.
        instruction = testbench.common.extract_instruction(request, context=None)
        (
            error_code,
            after_bytes,
            test_id,
        ) = testbench.common.get_retry_uploads_error_after_bytes(db, request)
        if error_code or instruction == "return-503-after-256K":
            if instruction == "return-503-after-256K":
                error_code = 503
                after_bytes = 262144
            testbench.common.handle_retry_uploads_error_after_bytes(
                upload,
                data,
                db,
                error_code,
                after_bytes,
                last_byte_persisted,
                chunk_first_byte,
                chunk_last_byte,
                test_id,
            )

        testbench.common.extract_instruction(request, context=None)
        (
            stall_time,
            after_bytes,
            test_id,
        ) = testbench.common.get_stall_uploads_after_bytes(db, request)

        if stall_time:
            testbench.common.handle_stall_uploads_after_bytes(
                upload,
                data,
                db,
                stall_time,
                after_bytes,
                test_id,
            )
        # The testbench should ignore any request bytes that have already been persisted,
        # to be aligned with GCS behavior (https://cloud.google.com/storage/docs/resumable-uploads#resent-data).
        # Thus we validate chunk_first_byte against last_byte_persisted.
        range_start = 0
        if chunk_first_byte != "*":
            if (
                last_byte_persisted != 0
                and int(chunk_first_byte) <= last_byte_persisted
            ):
                range_start = last_byte_persisted - int(chunk_first_byte) + 1
        if range_start:
            data = testbench.common.partial_media(
                data, range_end=(chunk_last_byte + 1), range_start=range_start
            )
        upload.media += data
        upload.complete = total_object_size == len(upload.media) or (
            chunk_last_byte + 1 == total_object_size
        )
    else:
        upload.media += data
        upload.complete = True
    if upload.complete:
        blob, _ = gcs_type.object.Object.init(
            upload.request, upload.metadata, upload.media, upload.bucket, False, None
        )
        blob.metadata.metadata["x_emulator_transfer_encoding"] = ":".join(
            upload.transfer
        )
        blob.metadata.metadata["x_emulator_upload"] = "resumable"
        blob.metadata.metadata["x_emulator_custom_header"] = str(custom_header_value)
        db.insert_object(
            bucket_name,
            blob,
            context=None,
            preconditions=testbench.common.make_json_preconditions(upload.request),
        )
        projection = testbench.common.extract_projection(upload.request, "noAcl", None)
        fields = upload.request.args.get("fields", None)
        return testbench.common.filter_response_rest(
            blob.rest_metadata(), projection, fields
        )
    else:
        # If request header "X-GUploader-No-308: yes" is included, instead of returning 308
        # Resume Incomplete, return 200 with a response header X-HTTP-Status-Code-Override: 308
        # See more at go/scotty-faq
        override_308 = request.headers.get("X-Guploader-No-308") == "yes"
        return upload.resumable_status_rest(override_308=override_308)


@upload.route("/b/<bucket_name>/o", methods=["DELETE"])
@retry_test(method="storage.objects.delete")
def delete_resumable_upload(bucket_name):
    upload_id = flask.request.args.get("upload_id")
    db.delete_upload(upload_id, None)
    return flask.make_response("", 499, {"content-length": 0})


# === SERVER === #

# Define the WSGI application to handle HMAC key and service account requests
(PROJECTS_HANDLER_PATH, projects_app) = projects_rest_server.get_projects_app(db)

# Define the WSGI application to handle IAM requests
(IAM_HANDLER_PATH, iam_app) = iam_rest_server.get_iam_app()

server = flask.Flask(__name__)
server.debug = False
server.register_error_handler(Exception, testbench.error.RestException.handler)
server.wsgi_app = DispatcherMiddleware(
    root,
    {
        "/httpbin": echo.app(),
        GCS_HANDLER_PATH: gcs,
        DOWNLOAD_HANDLER_PATH: download,
        UPLOAD_HANDLER_PATH: upload,
        PROJECTS_HANDLER_PATH: projects_app,
        IAM_HANDLER_PATH: iam_app,
    },
)


def _run():
    logging.basicConfig()
    return server


def _main():
    parser = argparse.ArgumentParser(
        description="A testbench for the GCS client libraries"
    )
    parser.add_argument("--port", default=0, type=int)
    args = parser.parse_args()
    serving.run_simple(
        "localhost",
        port=args.port,
        application=_run(),
        use_reloader=True,
        threaded=True,
    )


if __name__ == "__main__":
    _main()
