# Copyright 2022 Google LLC
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

"""Echo back HTTP requests for low-level integration tests."""

import flask

import http
import json

import testbench.error

_echo = flask.Flask(__name__)
_echo.debug = False
_echo.register_error_handler(Exception, testbench.error.RestException.handler)


def _headers_dict(request):
    """Return the request headers as a dictionary."""
    return {key: value for key, value in request.headers.items()}


def _common_payload(request):
    payload = {
        "args": request.args,
        "headers": _headers_dict(request),
        "origin": request.origin,
        "url": request.url,
    }
    if request.form is not None and len(request.form) != 0:
        payload["form"] = {key: value for key, value in request.form.items()}
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            payload["json"] = json.loads(request.data)
        except:
            pass
    return payload


@_echo.route("/delete", methods=["DELETE"])
def delete():
    payload = _common_payload(flask.request)
    return flask.make_response(
        json.dumps(payload), 200, {"content-type": "application/json"}
    )


@_echo.route("/get", methods=["GET"])
def get():
    payload = _common_payload(flask.request)
    return flask.make_response(
        json.dumps(payload), 200, {"content-type": "application/json"}
    )


@_echo.route("/patch", methods=["PATCH"])
def patch():
    payload = _common_payload(flask.request)
    payload["data"] = flask.request.data.decode("utf-8")
    return flask.make_response(
        json.dumps(payload), 200, {"content-type": "application/json"}
    )


@_echo.route("/post", methods=["POST"])
def post():
    payload = _common_payload(flask.request)
    payload["data"] = flask.request.data.decode("utf-8")
    return flask.make_response(
        json.dumps(payload), 200, {"content-type": "application/json"}
    )


@_echo.route("/put", methods=["PUT"])
def put():
    payload = _common_payload(flask.request)
    payload["data"] = flask.request.data.decode("utf-8")
    return flask.make_response(
        json.dumps(payload), 200, {"content-type": "application/json"}
    )


@_echo.route("/status/<text_code>", methods=["DELETE", "GET", "PATCH", "POST", "PUT"])
def status(text_code):
    code = int(text_code)
    if code == 418:
        # Python 3.6 does not seem to know about the all important 418 error code.
        return flask.make_response(
            "Server refuses to brew coffee because it is a teapot.",
            code,
            {"content-type": "text/plain"},
        )
    status = http.HTTPStatus(code)
    return flask.make_response(status.description, code, {"content-type": "text/plain"})


@_echo.route("/headers", methods=["GET"])
def headers():
    payload = {"headers": _headers_dict(flask.request)}
    return flask.make_response(
        json.dumps(payload), 200, {"content-type": "application/json"}
    )


@_echo.route("/response-headers", methods=["GET", "POST"])
def response_headers():
    payload = {key: value for key, value in flask.request.args.items()}
    payload["content-type"] = "application/json"
    payload["content-length"] = "%d"
    length = len(json.dumps(payload))
    # Consider the case where `length` has more than two digits.
    # Replacing `%d` with the value of `length` will increase the length
    # of the dumped JSON object.  This silly loop handles that case, there
    # are probably more efficient and elegant wants to handle this, but none
    # simpler (I think).
    while True:
        payload["content-length"] = "%d" % length
        actual = len(json.dumps(payload))
        if length == actual:
            break
        length = actual
    return flask.make_response(json.dumps(payload), 200, payload)


def _streamer(payload, count):
    for id in range(0, count):
        payload["id"] = id
        yield json.dumps(payload) + "\n"


@_echo.route("/stream/<count>", methods=["GET"])
def stream(count):
    payload = _common_payload(flask.request)
    generator = _streamer(payload.copy(), int(count))
    return _echo.response_class(generator, 200, {"content-type": "application/json"})


@_echo.route("/anything", methods=["DELETE", "GET", "PATCH", "POST", "PUT"])
def anything():
    payload = _common_payload(flask.request)
    payload["method"] = flask.request.method
    payload["data"] = flask.request.data.decode("utf-8")
    return flask.make_response(
        json.dumps(payload), 200, {"content-type": "application/json"}
    )


def app():
    return _echo
