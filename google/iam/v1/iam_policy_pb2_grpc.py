# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
# Copyright 2024 Google LLC
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

"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

from google.iam.v1 import iam_policy_pb2 as google_dot_iam_dot_v1_dot_iam__policy__pb2
from google.iam.v1 import policy_pb2 as google_dot_iam_dot_v1_dot_policy__pb2

GRPC_GENERATED_VERSION = '1.70.0'
GRPC_VERSION = grpc.__version__
_version_not_supported = False

try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    raise RuntimeError(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in google/iam/v1/iam_policy_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
    )


class IAMPolicyStub(object):
    """API Overview

    Manages Identity and Access Management (IAM) policies.

    Any implementation of an API that offers access control features
    implements the google.iam.v1.IAMPolicy interface.

    ## Data model

    Access control is applied when a principal (user or service account), takes
    some action on a resource exposed by a service. Resources, identified by
    URI-like names, are the unit of access control specification. Service
    implementations can choose the granularity of access control and the
    supported permissions for their resources.
    For example one database service may allow access control to be
    specified only at the Table level, whereas another might allow access control
    to also be specified at the Column level.

    ## Policy Structure

    See google.iam.v1.Policy

    This is intentionally not a CRUD style API because access control policies
    are created and deleted implicitly with the resources to which they are
    attached.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.SetIamPolicy = channel.unary_unary(
                '/google.iam.v1.IAMPolicy/SetIamPolicy',
                request_serializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.SetIamPolicyRequest.SerializeToString,
                response_deserializer=google_dot_iam_dot_v1_dot_policy__pb2.Policy.FromString,
                _registered_method=True)
        self.GetIamPolicy = channel.unary_unary(
                '/google.iam.v1.IAMPolicy/GetIamPolicy',
                request_serializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.GetIamPolicyRequest.SerializeToString,
                response_deserializer=google_dot_iam_dot_v1_dot_policy__pb2.Policy.FromString,
                _registered_method=True)
        self.TestIamPermissions = channel.unary_unary(
                '/google.iam.v1.IAMPolicy/TestIamPermissions',
                request_serializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsRequest.SerializeToString,
                response_deserializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsResponse.FromString,
                _registered_method=True)


class IAMPolicyServicer(object):
    """API Overview

    Manages Identity and Access Management (IAM) policies.

    Any implementation of an API that offers access control features
    implements the google.iam.v1.IAMPolicy interface.

    ## Data model

    Access control is applied when a principal (user or service account), takes
    some action on a resource exposed by a service. Resources, identified by
    URI-like names, are the unit of access control specification. Service
    implementations can choose the granularity of access control and the
    supported permissions for their resources.
    For example one database service may allow access control to be
    specified only at the Table level, whereas another might allow access control
    to also be specified at the Column level.

    ## Policy Structure

    See google.iam.v1.Policy

    This is intentionally not a CRUD style API because access control policies
    are created and deleted implicitly with the resources to which they are
    attached.
    """

    def SetIamPolicy(self, request, context):
        """Sets the access control policy on the specified resource. Replaces any
        existing policy.

        Can return `NOT_FOUND`, `INVALID_ARGUMENT`, and `PERMISSION_DENIED` errors.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetIamPolicy(self, request, context):
        """Gets the access control policy for a resource.
        Returns an empty policy if the resource exists and does not have a policy
        set.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def TestIamPermissions(self, request, context):
        """Returns permissions that a caller has on the specified resource.
        If the resource does not exist, this will return an empty set of
        permissions, not a `NOT_FOUND` error.

        Note: This operation is designed to be used for building permission-aware
        UIs and command-line tools, not for authorization checking. This operation
        may "fail open" without warning.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_IAMPolicyServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'SetIamPolicy': grpc.unary_unary_rpc_method_handler(
                    servicer.SetIamPolicy,
                    request_deserializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.SetIamPolicyRequest.FromString,
                    response_serializer=google_dot_iam_dot_v1_dot_policy__pb2.Policy.SerializeToString,
            ),
            'GetIamPolicy': grpc.unary_unary_rpc_method_handler(
                    servicer.GetIamPolicy,
                    request_deserializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.GetIamPolicyRequest.FromString,
                    response_serializer=google_dot_iam_dot_v1_dot_policy__pb2.Policy.SerializeToString,
            ),
            'TestIamPermissions': grpc.unary_unary_rpc_method_handler(
                    servicer.TestIamPermissions,
                    request_deserializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsRequest.FromString,
                    response_serializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'google.iam.v1.IAMPolicy', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('google.iam.v1.IAMPolicy', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class IAMPolicy(object):
    """API Overview

    Manages Identity and Access Management (IAM) policies.

    Any implementation of an API that offers access control features
    implements the google.iam.v1.IAMPolicy interface.

    ## Data model

    Access control is applied when a principal (user or service account), takes
    some action on a resource exposed by a service. Resources, identified by
    URI-like names, are the unit of access control specification. Service
    implementations can choose the granularity of access control and the
    supported permissions for their resources.
    For example one database service may allow access control to be
    specified only at the Table level, whereas another might allow access control
    to also be specified at the Column level.

    ## Policy Structure

    See google.iam.v1.Policy

    This is intentionally not a CRUD style API because access control policies
    are created and deleted implicitly with the resources to which they are
    attached.
    """

    @staticmethod
    def SetIamPolicy(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/google.iam.v1.IAMPolicy/SetIamPolicy',
            google_dot_iam_dot_v1_dot_iam__policy__pb2.SetIamPolicyRequest.SerializeToString,
            google_dot_iam_dot_v1_dot_policy__pb2.Policy.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetIamPolicy(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/google.iam.v1.IAMPolicy/GetIamPolicy',
            google_dot_iam_dot_v1_dot_iam__policy__pb2.GetIamPolicyRequest.SerializeToString,
            google_dot_iam_dot_v1_dot_policy__pb2.Policy.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def TestIamPermissions(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/google.iam.v1.IAMPolicy/TestIamPermissions',
            google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsRequest.SerializeToString,
            google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)
