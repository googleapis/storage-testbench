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

import flask
import httpbin
import json
from functools import wraps
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from google.cloud.storage_v1.proto.storage_resources_pb2 import CommonEnums
from google.protobuf import json_format

import gcs as gcs_type
import testbench


db = testbench.database.Database.init()
grpc_port = 0

# === DEFAULT ENTRY FOR REST SERVER === #
root = flask.Flask(__name__)
root.debug = False
root.register_error_handler(Exception, testbench.error.RestException.handler)


@root.route("/")
def index():
    return "OK"


def xml_put_object(bucket_name, object_name):
    db.insert_test_bucket(None)
    bucket = db.get_bucket_without_generation(bucket_name, None).metadata
    blob, fake_request = gcs_type.object.Object.init_xml(
        flask.request, bucket, object_name
    )
    db.insert_object(fake_request, bucket_name, blob, None)
    response = flask.make_response("")
    response.headers["x-goog-hash"] = fake_request.headers.get("x-goog-hash")
    return response


def xml_get_object(bucket_name, object_name):
    fake_request = testbench.common.FakeRequest.init_xml(flask.request)
    blob = db.get_object(fake_request, bucket_name, object_name, False, None)
    return blob.rest_media(fake_request)


@root.route("/<path:object_name>", subdomain="<bucket_name>")
def root_get_object(bucket_name, object_name):
    return xml_get_object(bucket_name, object_name)


@root.route("/<bucket_name>/<path:object_name>", subdomain="")
def root_get_object_with_bucket(bucket_name, object_name):
    return xml_get_object(bucket_name, object_name)


@root.route("/<path:object_name>", subdomain="<bucket_name>", methods=["PUT"])
def root_put_object(bucket_name, object_name):
    return xml_put_object(bucket_name, object_name)


@root.route("/<bucket_name>/<path:object_name>", subdomain="", methods=["PUT"])
def root_put_object_with_bucket(bucket_name, object_name):
    return xml_put_object(bucket_name, object_name)


# Needs to be defined in emulator.py to keep context of flask and db global variables
def retry_test(method):
    db.insert_supported_methods([method])

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            response_handler = testbench.common.handle_retry_test_instruction(
                db, flask.request, method
            )
            return response_handler(func(*args, **kwargs))

        return wrapper

    return decorator


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
    retry_test = db.insert_retry_test(test_instruction_set)
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


# === WSGI APP TO HANDLE JSON API === #
GCS_HANDLER_PATH = "/storage/v1"
gcs = flask.Flask(__name__)
gcs.debug = False
gcs.register_error_handler(Exception, testbench.error.RestException.handler)


# === BUCKET === #


@gcs.route("/b", methods=["GET"])
@retry_test(method="storage.buckets.list")
def bucket_list():
    db.insert_test_bucket(None)
    project = flask.request.args.get("project")
    projection = flask.request.args.get("projection", "noAcl")
    fields = flask.request.args.get("fields", None)
    response = {
        "kind": "storage#buckets",
        "items": [
            bucket.rest() for bucket in db.list_bucket(flask.request, project, None)
        ],
    }
    return testbench.common.filter_response_rest(response, projection, fields)


@gcs.route("/b", methods=["POST"])
@retry_test(method="storage.buckets.insert")
def bucket_insert():
    db.insert_test_bucket(None)
    bucket, projection = gcs_type.bucket.Bucket.init(flask.request, None)
    fields = flask.request.args.get("fields", None)
    db.insert_bucket(flask.request, bucket, None)
    return testbench.common.filter_response_rest(bucket.rest(), projection, fields)


@gcs.route("/b/<bucket_name>")
@retry_test(method="storage.buckets.get")
def bucket_get(bucket_name):
    db.insert_test_bucket(None)
    db.insert_test_bucket(None)
    bucket = db.get_bucket(flask.request, bucket_name, None)
    projection = testbench.common.extract_projection(
        flask.request, CommonEnums.Projection.NO_ACL, None
    )
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(bucket.rest(), projection, fields)


@gcs.route("/b/<bucket_name>", methods=["PUT"])
@retry_test(method="storage.buckets.update")
def bucket_update(bucket_name):
    db.insert_test_bucket(None)
    bucket = db.get_bucket(flask.request, bucket_name, None)
    bucket.update(flask.request, None)
    projection = testbench.common.extract_projection(
        flask.request, CommonEnums.Projection.FULL, None
    )
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(bucket.rest(), projection, fields)


@gcs.route("/b/<bucket_name>", methods=["PATCH", "POST"])
@retry_test(method="storage.buckets.patch")
def bucket_patch(bucket_name):
    testbench.common.enforce_patch_override(flask.request)
    bucket = db.get_bucket(flask.request, bucket_name, None)
    bucket.patch(flask.request, None)
    projection = testbench.common.extract_projection(
        flask.request, CommonEnums.Projection.FULL, None
    )
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(bucket.rest(), projection, fields)


@gcs.route("/b/<bucket_name>", methods=["DELETE"])
@retry_test(method="storage.buckets.delete")
def bucket_delete(bucket_name):
    db.delete_bucket(flask.request, bucket_name, None)
    return ""


# === BUCKET ACL === #


@gcs.route("/b/<bucket_name>/acl")
@retry_test(method="storage.bucket_acl.list")
def bucket_acl_list(bucket_name):
    bucket = db.get_bucket(flask.request, bucket_name, None)
    response = {"kind": "storage#bucketAccessControls", "items": []}
    for acl in bucket.metadata.acl:
        acl_rest = json_format.MessageToDict(acl)
        acl_rest["kind"] = "storage#bucketAccessControl"
        response["items"].append(acl_rest)
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl", methods=["POST"])
@retry_test(method="storage.bucket_acl.insert")
def bucket_acl_insert(bucket_name):
    bucket = db.get_bucket(flask.request, bucket_name, None)
    acl = bucket.insert_acl(flask.request, None)
    response = json_format.MessageToDict(acl)
    response["kind"] = "storage#bucketAccessControl"
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl/<entity>")
@retry_test(method="storage.bucket_acl.get")
def bucket_acl_get(bucket_name, entity):
    bucket = db.get_bucket(flask.request, bucket_name, None)
    acl = bucket.get_acl(entity, None)
    response = json_format.MessageToDict(acl)
    response["kind"] = "storage#bucketAccessControl"
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PUT"])
@retry_test(method="storage.bucket_acl.update")
def bucket_acl_update(bucket_name, entity):
    bucket = db.get_bucket(flask.request, bucket_name, None)
    acl = bucket.update_acl(flask.request, entity, None)
    response = json_format.MessageToDict(acl)
    response["kind"] = "storage#bucketAccessControl"
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PATCH", "POST"])
@retry_test(method="storage.bucket_acl.patch")
def bucket_acl_patch(bucket_name, entity):
    testbench.common.enforce_patch_override(flask.request)
    bucket = db.get_bucket(flask.request, bucket_name, None)
    acl = bucket.patch_acl(flask.request, entity, None)
    response = json_format.MessageToDict(acl)
    response["kind"] = "storage#bucketAccessControl"
    fields = flask.request.args.get("fields", None)
    return testbench.common.filter_response_rest(response, None, fields)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["DELETE"])
@retry_test(method="storage.bucket_acl.delete")
def bucket_acl_delete(bucket_name, entity):
    bucket = db.get_bucket(flask.request, bucket_name, None)
    bucket.delete_acl(entity, None)
    return ""


# === SERVER === #

# Define the WSGI application to handle HMAC key requests
(PROJECTS_HANDLER_PATH, projects_app) = gcs_type.project.get_projects_app()

# Define the WSGI application to handle IAM requests
(IAM_HANDLER_PATH, iam_app) = gcs_type.iam.get_iam_app()

server = flask.Flask(__name__)
server.debug = False
server.register_error_handler(Exception, testbench.error.RestException.handler)
server.wsgi_app = testbench.handle_gzip.HandleGzipMiddleware(
    DispatcherMiddleware(
        root,
        {
            "/httpbin": httpbin.app,
            GCS_HANDLER_PATH: gcs,
            PROJECTS_HANDLER_PATH: projects_app,
            IAM_HANDLER_PATH: iam_app,
        },
    )
)

httpbin.app.register_error_handler(Exception, testbench.error.RestException.handler)
