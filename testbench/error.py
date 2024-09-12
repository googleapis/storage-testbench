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

"""Helper functions to create errors for both gRPC and REST servers."""

import json
import traceback

import flask
import grpc
from werkzeug.exceptions import HTTPException


class RestException(Exception):
    def __init__(self, msg, code):
        super().__init__()
        self.msg = msg
        self.code = code

    def as_response(self):
        # Include both code and message so we follow the schema outlined in
        # https://cloud.google.com/apis/design/errors#error_model and some
        # clients depend on code being specified, otherwise behavior is
        # undefined.
        return flask.make_response(
            flask.jsonify(error={"code": self.code, "message": self.msg}),
            self.code,
        )

    @staticmethod
    def handler(ex):
        if isinstance(ex, RestException):
            return ex.as_response()
        elif isinstance(ex, HTTPException):
            return ex
        else:
            msg = traceback.format_exception(type(ex), ex, ex.__traceback__)
            return RestException("".join(msg), 500).as_response()


def _simple_json_error(msg):
    return json.dumps({"error": {"errors": [{"domain": "global", "message": msg}]}})


def generic(msg, rest_code, grpc_code, context):
    """Generate the appropriate error for REST or gRPC handlers."""
    if context is not None:
        context.abort(grpc_code, msg)
    else:
        raise RestException(msg, rest_code)


def csek(context, rest_code=400, grpc_code=grpc.StatusCode.INVALID_ARGUMENT):
    """A detailed error generated when CSEK key validation fails."""
    msg = "Missing a SHA256 hash of the encryption key, or it is not"
    msg += " base64 encoded, or it does not match the encryption key."
    link = "https://cloud.google.com/storage/docs/encryption/customer-supplied-keys"
    error_msg = json.dumps(
        {
            "error": {
                "errors": [
                    {
                        "domain": "global",
                        "reason": "customerEncryptionKeySha256IsInvalid",
                        "message": msg,
                        "extendedHelp": link,
                    }
                ],
                "code": rest_code,
                "message": msg,
            }
        }
    )
    generic(error_msg, rest_code, grpc_code, context)


def invalid(msg, context, rest_code=400, grpc_code=grpc.StatusCode.INVALID_ARGUMENT):
    """A fairly generic error for invalid values in arguments."""
    generic(_simple_json_error("%s is invalid." % msg), rest_code, grpc_code, context)


def missing(name, context, rest_code=400, grpc_code=grpc.StatusCode.INVALID_ARGUMENT):
    """Error returned when an argument or value is missing."""
    generic(_simple_json_error("Missing %s." % name), rest_code, grpc_code, context)


def mismatch(
    msg,
    expect,
    actual,
    context,
    rest_code=412,
    grpc_code=grpc.StatusCode.FAILED_PRECONDITION,
):
    """The error returned when if*Match or If-Match pre-conditions fail."""
    msg = "%s validation failed. Expected = %s vs Actual = %s." % (
        msg,
        str(expect),
        str(actual),
    )
    generic(_simple_json_error(msg), rest_code, grpc_code, context)

def not_soft_deleted(
        context,
        rest_code=412,
        grpc_code=grpc.StatusCode.FAILED_PRECONDITION
):
    """This error is returned when object is not soft deleted but is either live or noncurrent"""
    msg = "objectNotSoftDeleted"
    generic(_simple_json_error(msg), rest_code, grpc_code, context)


def notchanged(msg, context, rest_code=304, grpc_code=grpc.StatusCode.ABORTED):
    """Error returned when if*NotMatch or If-None-Match pre-conditions fail."""
    generic(
        _simple_json_error("%s validation failed." % msg), rest_code, grpc_code, context
    )


def notfound(name, context, rest_code=404, grpc_code=grpc.StatusCode.NOT_FOUND):
    """Error returned when a resource (Object, Bucket, Notification, etc.) is not found."""
    generic(
        _simple_json_error("%s does not exist." % name), rest_code, grpc_code, context
    )


def notallowed(context=None, rest_code=405, grpc_code=None):
    """Error returned when a method is not allowed."""
    generic(_simple_json_error("method is not allowed"), rest_code, grpc_code, context)


def already_exists(context=None):
    """Error returned when a resource already exists."""
    generic(
        _simple_json_error("resource already exists"),
        rest_code=409,
        grpc_code=grpc.StatusCode.ALREADY_EXISTS,
        context=context,
    )


def range_not_satisfiable(
    context=None, rest_code=416, grpc_code=grpc.StatusCode.OUT_OF_RANGE
):
    """Error returned when request range is not satisfiable."""
    generic(
        _simple_json_error("request range not satisfiable"),
        rest_code,
        grpc_code,
        context,
    )


def unimplemented(msg, context, rest_code=501, grpc_code=grpc.StatusCode.UNIMPLEMENTED):
    """Error returned when an operation is not implemented/supported."""
    generic(
        _simple_json_error("%s is not implemented." % msg),
        rest_code,
        grpc_code,
        context,
    )


def inject_error(context, rest_code, grpc_code, msg=""):
    """Inject error in grpc_server forced by the Retry Test API."""
    msg = "Retry Test: Caused a %s. %s" % (grpc_code, msg)
    generic(_simple_json_error(msg), rest_code, grpc_code, context)
