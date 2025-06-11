import os
import re
from abc import abstractmethod
from pathlib import Path

from dotenv import load_dotenv

from san2patch.context import San2PatchValidatorManager
from san2patch.dataset.base_dataset import BaseDataset
from san2patch.utils.cmd import BaseCommander
from san2patch.utils.docker import DockerHelper


class BaseValidator(BaseCommander):
    def __init__(self, vuln_id: str, project_name: str, *args, **kwargs):
        super().__init__(*args, **kwargs)

        load_dotenv(override=True)

        self.vuln_id = vuln_id
        self.project_name = project_name

    @abstractmethod
    def setup(self):
        raise NotImplementedError

    @abstractmethod
    def patch(self):
        raise NotImplementedError

    @abstractmethod
    def build_test(self):
        raise NotImplementedError

    @abstractmethod
    def build_func(self):
        raise NotImplementedError

    @abstractmethod
    def functionality_test(self):
        raise NotImplementedError

    @abstractmethod
    def vulnerability_test(self):
        raise NotImplementedError

    @abstractmethod
    def run(self):
        raise NotImplementedError


class FinalTestValidator(BaseValidator):
    name = "final-test"

    def __init__(
        self,
        vuln_data,
        stage_id,
        experiment_name: str | None = None,
        docker_id: str | None = None,
        *args,
        **kwargs,
    ):
        super().__init__(vuln_data["bug_id"], vuln_data["subject"], *args, **kwargs)

        self.stage_id = stage_id

        self.main_dir = (Path(os.getenv("DATASET_FINAL_DIR")) / self.name).resolve()

        self.binary_path: str = vuln_data["binary_path"]
        self.crash_input: str = vuln_data["crash_input"]
        if len(vuln_data["exploit_file_list"]) == 0:
            self.exploit_file = None
        else:
            self.exploit_file: str = vuln_data["exploit_file_list"][0].split("/")[-1]

        # Inside the host
        if experiment_name is not None:
            self.gen_diff_dir = os.path.join(
                self.main_dir, f"gen_diff_{experiment_name}"
            )
        else:
            self.gen_diff_dir = os.path.join(self.main_dir, "gen_diff")

        self.container_id = docker_id or San2PatchValidatorManager().docker_id

        self.run_dir = os.path.join(self.gen_diff_dir, self.vuln_id, self.stage_id)

        # Inside the docker
        self.data_dir = f"/san2patch-benchmark/{self.project_name}/{self.vuln_id}"
        self.experiment_dir = (
            f"/experiment/san2patch-benchmark/{self.project_name}/{self.vuln_id}"
        )
        self.experiment_func_dir = (
            f"/experiment_func/san2patch-benchmark/{self.project_name}/{self.vuln_id}"
        )
        # self.reproduce_cmd = f"./{self.data_dir}/test.sh {self.exploit_file}".strip()
        # self.reproduce_cmd = f"./test.sh {self.exploit_file}".strip()

    def setup(self):
        self.logger.info("Setting up the docker container for validating patch...")

        if self.container_id is None:
            self.container_id = DockerHelper().get_benchmark_container_id()

        if self.container_id is None or self.container_id == "":
            raise ValueError("Container not found.")

        # Remove all diff files from the previous run inside the docker
        # The remove script is in "/experiment/san2patch-benchmark/clear.sh"
        # self.run_cmd(f'docker exec {self.container_id} bash -c "cd /experiment/san2patch-benchmark && ./clear.sh"', cwd=self.main_dir, quiet=True)

        # Remove just the diff file for the current vuln_id
        self.run_cmd(
            f'docker exec {self.container_id} bash -c "ls {self.experiment_dir}/{self.vuln_id}.diff && rm -f {self.experiment_dir}/{self.vuln_id}.diff"',
            cwd=self.main_dir,
            quiet=True,
        )

        # Check if the data directory exists
        ret_code, _, _ = self.run_cmd(
            f'docker exec {self.container_id} bash -c "ls {self.experiment_dir}"',
            cwd=self.main_dir,
            quiet=True,
        )

        if ret_code != 0:
            raise ValueError("Data directory not found.")

        # Reset the git repository
        self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.experiment_dir}/src && git reset --hard"',
            cwd=self.main_dir,
            quiet=True,
        )

        self.logger.debug(f"Container ID: {self.container_id}")
        self.logger.debug("Docker container setup completed.")

    def patch(self):
        self.logger.info("Applying the patch...")

        host_patch_file = os.path.join(
            self.gen_diff_dir, self.vuln_id, self.stage_id, f"{self.vuln_id}.diff"
        )
        docker_patch_file = os.path.join(self.experiment_dir, f"{self.vuln_id}.diff")

        # Copy generated patch file into the container
        self.run_cmd(
            f"docker cp {host_patch_file} {self.container_id}:{docker_patch_file}",
            cwd=self.main_dir,
            expect_error=True,
        )

        # Apply the patch
        ret, _, stderr = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.experiment_dir}/src && git apply --ignore-whitespace {docker_patch_file}"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )
        _, _, _ = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.experiment_func_dir}/src && git reset --hard && git apply --ignore-whitespace {docker_patch_file}"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )

        if ret != 0:
            self.logger.error("Patch failed to apply.")
            return False, stderr

        else:
            self.logger.info("Patch applied successfully.")
            return True, None

    def build_test(self):
        self.logger.info("Building the project...")

        ret_code_c, _, stderr_c = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./config.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )
        ret_code_b, _, stderr_b = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./build.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )

        if ret_code_c != 0 or ret_code_b != 0:
            self.logger.error("Build failed.")

            return False, stderr_c if ret_code_c != 0 else stderr_b

        else:
            self.logger.info("Build completed.")

            return True, None

    def build_func(self):
        self.logger.info("Building the project...")

        ret_code_c, _, stderr_c = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./config_func.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )
        ret_code_b, _, stderr_b = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./build_func.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )

        if ret_code_c != 0 or ret_code_b != 0:
            self.logger.error(f"Build failed. {self.vuln_id}")

            return False, stderr_c if ret_code_c != 0 else stderr_b

        else:
            self.logger.info(f"Build completed. {self.vuln_id}")

            return True, None

    def functionality_test(self):
        self.logger.info("Testing the functionality...")

        # Build the project
        self.build_func()

        # Just run the test_func.sh in data_dir
        ret_code, _, stderr = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./test_func.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )

        if ret_code != 0:
            self.logger.error(f"Functionality test failed. {self.vuln_id}")
            return False, stderr
        else:
            self.logger.success(f"Functionality test passed. {self.vuln_id}")
            return True, None

    def vulnerability_test(self):
        self.logger.info("Testing the vulnerability...")

        # Try 1: Copy the error output to the host
        docker_vuln_out_file = os.path.join(
            self.experiment_dir, "src", self.binary_path + ".out"
        )
        host_vuln_out_file = os.path.join(self.run_dir, f"{self.vuln_id}.vuln.out")

        self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./test.sh {self.exploit_file}"',
            cwd=self.main_dir,
            expect_error=True,
        )

        # Copy sanitizer output to the host
        self.run_cmd(
            f"docker cp {self.container_id}:{docker_vuln_out_file} {host_vuln_out_file}",
            cwd=self.main_dir,
        )

        try:
            with open(host_vuln_out_file, "r", errors="ignore") as f_stderr:
                stderr = f_stderr.read()

                sanitizer_re_1 = r"ERROR: .+Sanitizer:"
                sanitizer_re_2 = r"SUMMARY: .+Sanitizer:"
                sanitizer_re_3 = r"runtime error:"

                # Check if the sanitizer is found
                if (
                    re.search(sanitizer_re_1, stderr)
                    or re.search(sanitizer_re_2, stderr)
                    or re.search(sanitizer_re_3, stderr)
                ):
                    self.logger.error(f"Sanitizer detected the crash. {self.vuln_id}")
                    self.logger.error(f"Patch was not successful. {self.vuln_id}")

                    san_output = BaseDataset.get_only_san_output(stderr)

                    return False, san_output
                else:
                    self.logger.success(f"Crash not found. {self.vuln_id}")
                    self.logger.success(f"Vulnerability test passed. {self.vuln_id}")

                    return True, None
        except FileNotFoundError:
            self.logger.error(
                "Sanitizer output not found. Please check the test.sh script."
            )

            return False, None

    def run(self):
        self.setup()
        self.patch()
        self.build_test()
        self.vulnerability_test()
