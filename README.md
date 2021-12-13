# Storage Testbench

**This is not an officially supported Google product**

This repository is used by Storage Client libraries to test integration tests locally
and reproduce Storage API transient errors. The testbench emulates the Storage API and
is expected to be used by Storage library maintainers.


## Table of Contents
- [Storage Testbench](#storage-testbench)
  - [Table of Contents](#table-of-contents)
  - [Issue Policy](#issue-policy)
  - [What is this testbench?](#what-is-this-testbench)
  - [When to use this testbench](#when-to-use-this-testbench)
  - [How to use this testbench](#how-to-use-this-testbench)
    - [Initial set up](#initial-set-up)
    - [Check that the testbench is running](#check-that-the-testbench-is-running)
  - [Updating Proto Files](#updating-proto-files)
  - [Force Failures](#force-failures)
    - [return-broken-stream](#return-broken-stream)
    - [return-corrupted-data](#return-corrupted-data)
    - [stall-always](#stall-always)
    - [stall-at-256KiB](#stall-at-256kib)
    - [return-503-after-256K](#return-503-after-256k)
    - [return-503-after-256K/retry-N](#return-503-after-256kretry-n)
  - [Retry Test API](#retry-test-api)
    - [Creating a new Retry Test](#creating-a-new-retry-test)
    - [Get a Retry Test resource](#get-a-retry-test-resource)
    - [Delete a Retry Test resource](#delete-a-retry-test-resource)
    - [Causing a failure using x-retry-test-id header](#causing-a-failure-using-x-retry-test-id-header)
    - [Forced Failures Supported](#forced-failures-supported)

## Issue Policy

Repository provides no dedicated support for issues filed.
Issues will be addressed when time permits.

## What is this testbench?

This testbench fakes the Google Cloud Storage (GCS) API. You can configure the GCS client libraries to make calls to this fake rather than to the actual API.
* The testbench fakes the JSON API, both over REST and gRPC. It has limited support for the XML API.
* Generally, the error codes are similar to the ones generated by GCS, but the error messages are not.
* The testbench performs far fewer error checks, and no permission checks (ACL/IAM).

## When to use this testbench

In general, this testbench is best suited for integration tests that are hard (or just annoying) to reliably run against production. The primary example of this are errors that make the client library go through its retry path.

This testbench can be useful to test HMAC keys, which are really hard to test against production due to quota restrictions.

It is useful as well to test features that are not yet deployed to production: you can implement them in the testbench and then write the library code before production is "ready".

## How to use this testbench

### Initial set up

1. [Set up python if you haven't already](https://cloud.google.com/python/docs/setup)
2. [Clone this repository](https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository-from-github/cloning-a-repository#cloning-a-repository)

   From the terminal:
   ```bash
   git clone https://github.com/googleapis/storage-testbench.git
   ```
3. Switch to the cloned directory:
   ```bash
   cd storage-testbench
    ```
4. [Create a virtual environment](https://cloud.google.com/python/docs/setup#installing_and_using_virtualenv)
    * keep this virtual environment active whenever you run the testbench
5. Install dependencies:
    ```bash
    pip install -e .
    ```

### Run the testbench

To start the testbench, run this command from a terminal:

```bash
gunicorn --bind "localhost:9000" --worker-class sync --threads 10 --reload --access-logfile - "testbench:run()"
```

> ⚠️ Ensure that the virtual environment you created to install the dependencies is active.


### Check that the testbench is running

Ensure the testbench is running by sending it a request from a different terminal, such as:

```bash
curl -X GET localhost:9000
```

The response you get should be: `OK`

Now you can use the testbench (while it's running) with the client libraries.

## Updating Proto Files

From time to time you may need to update the files generated by protobuf and
gRPC. To do so, clone the [protos](https://github.com/googleapis/googleapis) and
run the grpc_tools generator:

```shell
cd $HOME/storage-testbench

git -C $HOME clone https://github.com/googleapis/googleapis
# if it already exists, use
#    git -C $HOME pull 
git -C $HOME/googleapis checkout origin/preview -- google/storage/v2

pip install grpcio-tools
python -m grpc_tools.protoc -I$HOME/googleapis \
    --python_out=. --grpc_python_out=. \
    $HOME/googleapis/google/iam/v1/iam_policy.proto
python -m grpc_tools.protoc -I$HOME/googleapis \
    --python_out=. --grpc_python_out=. \
    $HOME/googleapis/google/iam/v1/options.proto
python -m grpc_tools.protoc -I$HOME/googleapis \
    --python_out=. --grpc_python_out=. \
    $HOME/googleapis/google/iam/v1/policy.proto
python -m grpc_tools.protoc -I$HOME/googleapis \
    --python_out=. --grpc_python_out=. \
    $HOME/googleapis/google/storage/v2/storage.proto
```

Then commit the files generated in `google/**`:

```shell
git commit -m"chore: update protos" google
```

## Force Failures

You can force the following failures by using the `x-goog-emulator-instructions` header.
The `x-goog-testbench-instructions` header is deprecated, but supported for
backwards compatibility and provides the same functionality as
`x-goog-emulator-instructions`, please change your code to use `x-goog-emulator-instructions` instead.

### return-broken-stream

Set request headers with `x-goog-emulator-instructions: return-broken-stream`.
Testbench will fail after sending 1024*1024 bytes.

### return-corrupted-data

Set request headers with `x-goog-emulator-instructions: return-corrupted-data`.
Testbench will return corrupted data.

### stall-always

Set request headers with `x-goog-emulator-instructions: stall-always`.
Testbench will stall at the beginning.

### stall-at-256KiB

Set request headers with `x-goog-emulator-instructions: stall-at-256KiB`.
Testbench will stall at 256KiB bytes.

### return-503-after-256K

Set request headers with `x-goog-emulator-instructions: return-503-after-256K`.
Testbench will return a `HTTP 503` after sending 256KiB bytes.

### return-503-after-256K/retry-N

Set request headers with `x-goog-emulator-instructions: return-503-after-256K/retry-1` up to `x-goog-emulator-instructions: return-503-after-256K/retry-N`.

For N==1 and N==2 behave like `return-305-after-256K`, for `N>=3` ignore the
failure instruction and return successfully. This is used to test failures during
retry, the client cooperates by sending the retry counter in the failure
instructions.


## Retry Test API

The "Retry Test API" offers a mechanism to describe more complex retry scenarios
while sending a single, constant header through all the HTTP requests from a
test program. Retry Test provides accounting of failures used to validate
the expected failures were experienced by the testbench and not accidentally missed.

Previous versions of the GCS testbench used a custom header in the RPC to
control the behavior of each RPC, for some test scenarios this required sending
different header with the first retry attempt vs. subsequent attempts. Producing
different headers in each attempt is not easy to implement with some client libraries.

Sending a constant header with all RPCs can be implemented across all client libraries,
and to some degree decouples the test setup from the test execution.

### Creating a new Retry Test

The following cURL request will create a Retry Test resource which emits a 503
when a buckets list operation is received by the testbench with the returned
retry test ID.

```bash
curl -X POST "http://localhost:9000/retry_test" -H 'Content-Type: application/json' \
     -d '{"instructions":{"storage.buckets.list": ["return-503"]}}'
```

### Get a Retry Test resource

Get Retry Test resource by id "1d05c20627844214a9ff7cbcf696317d".

```bash
curl -X GET "http://localhost:9000/retry_test/1d05c20627844214a9ff7cbcf696317d"
```

### Delete a Retry Test resource

Delete Retry Test resource by id "1d05c20627844214a9ff7cbcf696317d".

```bash
curl -X DELETE "http://localhost:9000/retry_test/1d05c20627844214a9ff7cbcf696317d"
```

### Causing a failure using x-retry-test-id header

The following cURL request will attempt to list buckets and the testbench will emit
a `503` error once based on the Retry Test created above. Subsequent list buckets
operations will succeed.

```bash
curl -H "x-retry-test-id: 1d05c20627844214a9ff7cbcf696317d" "http://localhost:9100/storage/v1/b?project=test"
```

### Forced Failures Supported

| Failure Id              | Description
| ----------------------- | ---
| return-X                                  | Testbench will fail with HTTP code provided for `X`, e.g. return-503 returns a 503
| return-X-after-YK                         | Testbench will return X after YKiB of uploaded data
| return-broken-stream-final-chunk-after-YB | Testbench will break connection on final chunk of a resumable upload after Y bytes.
| return-broken-stream                      | Testbench will fail after a few bytes
| return-reset-connection                   | Testbench will fail with a reset connection
