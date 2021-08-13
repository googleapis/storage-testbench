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
from functools import wraps
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from google.cloud.storage_v1.proto.storage_resources_pb2 import CommonEnums

import gcs as gcs_type
import testbench


db = testbench.database.Database.init()
grpc_port = 0
supported_methods = []

# === DEFAULT ENTRY FOR REST SERVER === #
root = flask.Flask(__name__)
root.debug = False
root.register_error_handler(Exception, testbench.error.RestException.handler)


@root.route("/")
def index():
    return "OK"


# === WSGI APP TO HANDLE JSON API === #
GCS_HANDLER_PATH = "/storage/v1"
gcs = flask.Flask(__name__)
gcs.debug = False
gcs.register_error_handler(Exception, testbench.error.RestException.handler)


# === BUCKET === #


@gcs.route("/b", methods=["GET"])
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
def bucket_insert():
    db.insert_test_bucket(None)
    bucket, projection = gcs_type.bucket.Bucket.init(flask.request, None)
    fields = flask.request.args.get("fields", None)
    db.insert_bucket(flask.request, bucket, None)
    return testbench.common.filter_response_rest(bucket.rest(), projection, fields)


@gcs.route("/b/<bucket_name>")
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
def bucket_delete(bucket_name):
    db.delete_bucket(flask.request, bucket_name, None)
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
