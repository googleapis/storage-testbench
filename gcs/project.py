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

"""Implement a class to simulate projects (service accounts and HMAC keys)."""

import base64
import random
import time

import flask

import testbench


class ServiceAccount(object):
    """Represent a service account and its HMAC keys."""

    key_id_generator = 20000

    @classmethod
    def next_key_id(cls):
        cls.key_id_generator += 1
        return "key-id-%d" % cls.key_id_generator

    def __init__(self, email):
        self.email = email
        self.keys = {}

    def insert_key(self, project_id):
        """Insert a new HMAC key to the service account."""
        key_id = ServiceAccount.next_key_id()
        secret = "".join(
            [random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(40)]
        )
        now = time.gmtime(time.time())
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", now)
        return self.keys.setdefault(
            key_id,
            {
                "kind": "storage#hmacKeyCreate",
                "secret": base64.b64encode(bytearray(secret, "utf-8")).decode("utf-8"),
                "generator": 1,
                "metadata": {
                    "accessId": "%s:%s" % (self.email, key_id),
                    "etag": base64.b64encode(bytearray("%d" % 1, "utf-8")).decode(
                        "utf-8"
                    ),
                    "id": key_id,
                    "kind": "storage#hmacKey",
                    "projectId": project_id,
                    "serviceAccountEmail": self.email,
                    "state": "ACTIVE",
                    "timeCreated": timestamp,
                    "updated": timestamp,
                },
            },
        )

    def key_items(self):
        """Return the keys in this service account as a list of JSON objects."""
        return [k.get("metadata") for k in self.keys.values()]

    def delete_key(self, key_id):
        """Delete an existing HMAC key from the service account."""
        key = self.keys.get(key_id)
        if key is None:
            testbench.error.notfound("key %s" % key_id, None)
        resource = key.get("metadata")
        if resource is None:
            testbench.error.missing("resource for HMAC key %s" % key_id, None)
        if resource.get("state") == "ACTIVE":
            testbench.error.invalid("Deleting ACTIVE key %s" % key_id, None)
        resource["state"] = "DELETED"
        self.keys.pop(key_id)
        return resource

    def get_key(self, key_id):
        """Get an existing HMAC key from the service account."""
        key = self.keys.get(key_id)
        if key is None:
            testbench.error.notfound("key %s" % key_id, None)
        metadata = key.get("metadata")
        if metadata is None:
            testbench.error.missing("resource for HMAC key %s" % key_id, None)
        return metadata

    def _check_etag(self, key_resource, etag, where):
        """Verify that ETag values match the current ETag."""
        expected = key_resource.get("etag")
        if etag is None or etag == expected:
            return
        testbench.error.mismatch(
            "ETag for `HmacKeys: update` in %s" % where, expected, etag, None
        )

    def update_key(self, key_id, payload):
        """Get an existing HMAC key from the service account."""
        key = self.keys.get(key_id)
        if key is None:
            testbench.error.notfound("key %s" % key_id, None)
        metadata = key.get("metadata")
        if metadata is None:
            testbench.error.missing("resource for HMAC key %s" % key_id, None)
        self._check_etag(metadata, payload.get("etag"), "payload")
        self._check_etag(metadata, flask.request.headers.get("if-match-etag"), "header")

        state = payload.get("state")
        if state not in ("ACTIVE", "INACTIVE"):
            testbench.error.invalid(
                "state `HmacKeys: update` request %s" % key_id, None
            )
        if metadata.get("state") == "DELETED":
            testbench.error.invalid(
                "Restoring DELETE key in `HmacKeys: update` request %s" % key_id, None
            )
        key["generator"] += 1
        metadata["state"] = state
        metadata["etag"] = base64.b64encode(
            bytearray("%d" % key["generator"], "utf-8")
        ).decode("utf-8")
        now = time.gmtime(time.time())
        metadata["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", now)
        return metadata


class GcsProject(object):
    """Represent a GCS project."""

    project_number_generator = 100000

    @classmethod
    def next_project_number(cls):
        cls.project_number_generator += 1
        return cls.project_number_generator

    def __init__(self, project_id):
        self.project_id = project_id
        self.project_number = GcsProject.next_project_number()
        self.service_accounts = {}

    def service_account_email(self):
        """Return the GCS service account email for this project."""
        username = "service-%d" % self.project_number
        domain = "gs-project-accounts.iam.gserviceaccount.com"
        return "%s@%s" % (username, domain)

    def insert_hmac_key(self, service_account):
        """Insert a new HMAC key (or an error)."""
        sa = self.service_accounts.setdefault(
            service_account, ServiceAccount(service_account)
        )
        return sa.insert_key(self.project_id)

    def service_account(self, service_account_email):
        """Return a ServiceAccount object given its email."""
        return self.service_accounts.get(service_account_email)

    def delete_hmac_key(self, access_id):
        """Remove a key from the project."""
        (service_account, key_id) = access_id.split(":", 2)
        sa = self.service_accounts.get(service_account)
        if sa is None:
            testbench.error.notfound("service account for key=%s" % access_id, None)
        return sa.delete_key(key_id)

    def get_hmac_key(self, access_id):
        """Get an existing key in the project."""
        (service_account, key_id) = access_id.split(":", 2)
        sa = self.service_accounts.get(service_account)
        if sa is None:
            testbench.error.notfound("service account for key=%s" % access_id, None)
        return sa.get_key(key_id)

    def update_hmac_key(self, access_id, payload):
        """Update an existing key in the project."""
        (service_account, key_id) = access_id.split(":", 2)
        sa = self.service_accounts.get(service_account, None)
        if sa is None:
            testbench.error.notfound("service account for key=%s" % access_id, None)
        return sa.update_key(key_id, payload)
