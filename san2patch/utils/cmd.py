import subprocess
import sys
from abc import ABC
from typing import NamedTuple

from san2patch.context import San2PatchLogger


class ProcessRunRet(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


class BaseCommander(ABC):
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.logger = San2PatchLogger().logger

    def docker_cmd(
        self, cmd: str | list[str], container_id: str, pipe: bool = False
    ) -> ProcessRunRet:
        if not self.quiet:
            self.logger.debug(f"Running CMD: {cmd} in container {container_id}")

        try:
            if not pipe:
                result = subprocess.run(
                    ["docker", "exec", container_id] + cmd,
                    check=True,
                    text=True,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                )
            else:
                result = subprocess.run(
                    ["docker", "exec", container_id] + cmd,
                    check=True,
                    text=True,
                    capture_output=True,
                )

            return ProcessRunRet(result.returncode, result.stdout, result.stderr)

        except subprocess.CalledProcessError as e:
            self.logger.error(
                f"Error occurred while running CMD: {cmd} in container {container_id}"
            )
            self.logger.error(e)

            return ProcessRunRet(e.returncode, e.stdout, e.stderr)

    def run_cmd(
        self,
        cmd: str | list[str],
        input: str | None = None,
        cwd: str = "./",
        pipe: bool = False,
        quiet: bool = None,
        timeout: int | None = None,
        stdout_file: str | None = None,
        stderr_file: str | None = None,
        expect_error: bool = False,
    ) -> ProcessRunRet:
        if quiet is None:
            quiet = self.quiet

        if not quiet:
            self.logger.debug(f"Running CMD: {cmd} at {cwd}")
        try:
            if quiet:
                result = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    cwd=cwd,
                    check=True,
                    text=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                )
            elif not pipe:
                result = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    cwd=cwd,
                    check=True,
                    text=True,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    timeout=timeout,
                )
            else:
                result = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    cwd=cwd,
                    check=True,
                    text=True,
                    capture_output=True,
                    timeout=timeout,
                )

            return ProcessRunRet(result.returncode, result.stdout, result.stderr)

        except subprocess.CalledProcessError as e:
            if not expect_error:
                self.logger.error(f"Error occurred while running CMD: {cmd} at {cwd}")
                self.logger.error(f"stdout: {e.stdout}")
                self.logger.error(f"stderr: {e.stderr}")

            return ProcessRunRet(e.returncode, e.stdout, e.stderr)

        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Timeout occurred while running CMD: {cmd} at {cwd}")
            self.logger.error(e)

            return ProcessRunRet(-1, e.stdout, e.stderr)

        finally:
            if stdout_file and result.stdout:
                with open(stdout_file, "a") as f:
                    f.write(result.stdout)
            if stderr_file and result.stderr:
                with open(stderr_file, "a") as f:
                    f.write(result.stderr)
