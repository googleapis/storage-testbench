#!/usr/bin/env python3
#
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

"""Unit test for testbench_waitress"""

import io
import platform
import subprocess
import sys
import unittest
from unittest.mock import patch

import waitress


class TestTestbenchRun(unittest.TestCase):
    def test_start_server_does_not_start_with_insufficient_number_of_arguments(self):
        test_three_argv = ["testbench_run.py", "localhost", "0"]
        with patch.object(sys, "argv", test_three_argv):
            import testbench_run

            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput  # redirecting stdout
            testbench_run.start_server()
            sys.stdout = sys.__stdout__  # restoring output stream to as it was before.

            self.assertEqual(
                capturedOutput.getvalue(),
                "Invalid number of arguments. Please provide 'testbench_run.py <hostname> <port> <number of threads>'.\n",
            )

    def test_start_server_starts_waitress_on_windows_platform(self):
        test_three_argv = ["testbench_run.py", "localhost", "0", "10"]
        mock_platform_system = unittest.mock.Mock(return_value="windows")
        mock_waitress_serve = unittest.mock.Mock(return_value=None)

        with patch.object(sys, "argv", test_three_argv), patch.object(
            platform, "system", mock_platform_system
        ), patch.object(waitress, "serve", mock_waitress_serve):
            import testbench_run

            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput  # redirecting stdout
            testbench_run.start_server()
            sys.stdout = sys.__stdout__  # restoring output stream to as it was before.

            self.assertEqual(
                capturedOutput.getvalue(),
                "Starting waitress server\n",
            )

    def test_start_server_starts_gunicorn_on_non_windows_platform(self):
        test_three_argv = ["testbench_run.py", "localhost", "0", "10"]
        mock_platform_system = unittest.mock.Mock(return_value="linux")
        mock_gunicorn_subprocess_run = unittest.mock.Mock(return_value=None)

        with patch.object(sys, "argv", test_three_argv), patch.object(
            platform, "system", mock_platform_system
        ), patch.object(subprocess, "run", mock_gunicorn_subprocess_run):
            import testbench_run

            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput  # redirecting stdout
            testbench_run.start_server()
            sys.stdout = sys.__stdout__  # restoring output stream to as it was before.

            self.assertEqual(
                capturedOutput.getvalue(),
                "Starting gunicorn server\n",
            )


if __name__ == "__main__":
    unittest.main()
