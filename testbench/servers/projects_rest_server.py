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

"""Implement the flask appthe `/storage/v1/<project-id>/` path."""

import json
import flask

from gcs import project
import testbench.common

_VALID_PROJECTS = {}
_PROJECTS_HANDLER_PATH = "/storage/v1/projects"


def get_project(project_id):
    """Find a project and return the GcsProject object."""
    # Dynamically create the projects. The GCS testbench does not have functions
    # to create projects, nor do we want to create such functions. The point is
    # to test the GCS client library, not the IAM client library.
    return _VALID_PROJECTS.setdefault(project_id, project.GcsProject(project_id))


def get_projects_app(db):

    retry_test = testbench.common.gen_retry_test_decorator(db)

    projects = flask.Flask(__name__)
    projects.debug = False
    projects.register_error_handler(Exception, testbench.error.RestException.handler)

    @projects.route("/<project_id>/serviceAccount")
    @retry_test("storage.serviceaccount.get")
    def projects_get(project_id):
        """Implement the `Projects.serviceAccount: get` API."""
        project = get_project(project_id)
        email = project.service_account_email()
        response = {"kind": "storage#serviceAccount", "email_address": email}
        fields = flask.request.args.get("fields", None)
        return testbench.common.filter_response_rest(response, None, fields)

    @projects.route("/<project_id>/hmacKeys", methods=["POST"])
    @retry_test("storage.hmacKey.create")
    def hmac_keys_insert(project_id):
        """Implement the `HmacKeys: insert` API."""
        project = get_project(project_id)
        service_account = flask.request.args.get("serviceAccountEmail")
        if service_account is None:
            testbench.error.missing("serviceAccountEmail", None)
        response = project.insert_hmac_key(service_account)
        fields = flask.request.args.get("fields", None)
        return testbench.common.filter_response_rest(response, None, fields)

    @projects.route("/<project_id>/hmacKeys")
    @retry_test("storage.hmacKey.list")
    def hmac_keys_list(project_id):
        """Implement the 'HmacKeys: list' API: return the HMAC keys in a project."""
        # Lookup the bucket, if this fails the bucket does not exist, and this
        # function should return an error.
        project = get_project(project_id)
        result = {
            "kind": "storage#hmacKeysMetadata",
            "next_page_token": "",
            "items": [],
        }

        state_filter = lambda x: x.get("state") != "DELETED"
        if flask.request.args.get("deleted") == "true":
            state_filter = lambda x: True

        items = []
        if flask.request.args.get("serviceAccountEmail"):
            sa = flask.request.args.get("serviceAccountEmail")
            service_account = project.service_account(sa)
            if service_account:
                items = service_account.key_items()
        else:
            for sa in project.service_accounts.values():
                items.extend(sa.key_items())

        result["items"] = [i for i in items if state_filter(i)]
        fields = flask.request.args.get("fields", None)
        return testbench.common.filter_response_rest(result, None, fields)

    @projects.route("/<project_id>/hmacKeys/<access_id>", methods=["DELETE"])
    @retry_test("storage.hmacKey.delete")
    def hmac_keys_delete(project_id, access_id):
        """Implement the `HmacKeys: delete` API."""
        project = get_project(project_id)
        project.delete_hmac_key(access_id)
        return ""

    @projects.route("/<project_id>/hmacKeys/<access_id>")
    @retry_test("storage.hmacKey.get")
    def hmac_keys_get(project_id, access_id):
        """Implement the `HmacKeys: get` API."""
        project = get_project(project_id)
        response = project.get_hmac_key(access_id)
        fields = flask.request.args.get("fields", None)
        return testbench.common.filter_response_rest(response, None, fields)

    @projects.route("/<project_id>/hmacKeys/<access_id>", methods=["PUT"])
    @retry_test("storage.hmacKey.update")
    def hmac_keys_update(project_id, access_id):
        """Implement the `HmacKeys: update` API."""
        project = get_project(project_id)
        payload = json.loads(flask.request.data)
        response = project.update_hmac_key(access_id, payload)
        fields = flask.request.args.get("fields", None)
        return testbench.common.filter_response_rest(response, None, fields)

    return _PROJECTS_HANDLER_PATH, projects
