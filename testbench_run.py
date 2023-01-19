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

import sys
import platform
import waitress
import testbench
import logging
import subprocess
from testbench_waitress import testbench_create_server

logger = logging.getLogger("waitress")
logger.setLevel(logging.INFO)


def start_server():
    if len(sys.argv) == 4:
        sock_host = sys.argv[1]
        sock_port = int(sys.argv[2])
        num_of_threads = int(sys.argv[3])
        sys.argv.clear()

        if platform.system().lower() == "windows":
            print("Starting waitress server")
            waitress.serve(
                testbench.run(),
                _server=testbench_create_server,
                host=sock_host,
                port=sock_port,
                threads=num_of_threads,
            )
        else:
            print("Starting gunicorn server")
            subprocess.run(
                [
                    "gunicorn",
                    f"--bind={sock_host}:{sock_port}",
                    "--worker-class=sync",
                    f"--threads={num_of_threads}",
                    "--reload",
                    "--access-logfile=-",
                    "testbench:run()",
                ]
            )

    else:
        print(
            "Invalid number of arguments. Please provide 'testbench_run.py <hostname> <port> <number of threads>'."
        )


if __name__ == "__main__":
    start_server()
