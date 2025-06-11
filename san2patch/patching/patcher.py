import json
import os
from typing import Literal, NamedTuple

from aim import Run
from dotenv import load_dotenv

from san2patch.context import init_context
from san2patch.patching.graph.ablation.cot.patching_graph import (
    CoTPatchState,
    generate_cot_patch_graph,
)
from san2patch.patching.graph.ablation.no_comprehend.patching_graph import (
    NoComprehendPatchState,
    generate_no_comprehend_patch_graph,
)
from san2patch.patching.graph.ablation.no_context.patching_graph import (
    NoContextPatchState,
    generate_no_context_patch_graph,
)
from san2patch.patching.graph.ablation.no_howtofix.patching_graph import (
    NoHowToFixPatchState,
    generate_no_howtofix_patch_graph,
)
from san2patch.patching.graph.ablation.zeroshot.patching_graph import (
    ZeroshotPatchState,
    generate_zeroshot_patch_graph,
)
from san2patch.patching.graph.patching_graph import (
    FullPatchState,
    generate_tot_patch_graph,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.validator import FinalTestValidator
from san2patch.utils.cmd import BaseCommander
from san2patch.utils.docker import DockerHelper
from san2patch.utils.enum import (
    SELECT_METHODS,
    TEMPERATURE_SETTING,
    VERSION_LIST,
    ExperimentStepEnum,
)
from san2patch.utils.enum import ExperimentResEnum as TestEvalRetCode


class San2Patcher(BaseCommander):
    def __init__(
        self,
        vuln_id: str,
        data_dir: str,
        mode: Literal["test"] = "test",
        LLMPatcher: BaseLLMPatcher = GPT4oPatcher,
        version: VERSION_LIST = "tot",
        aim_run: Run | None = None,
        experiment_name: str | None = None,
        retry_cnt: int = 1,
        docker_id: str | None = None,
        select_method: SELECT_METHODS = "sample",
        temperature_setting: TEMPERATURE_SETTING = "medium",
        *args,
        **kwargs,
    ):
        load_dotenv(override=True)

        super().__init__(*args, **kwargs)

        self.vuln_id = vuln_id
        self.data_dir = data_dir
        self.retry_cnt = retry_cnt
        self.docker_id = docker_id
        if self.docker_id is None:
            try:
                self.docker_id = DockerHelper().get_benchmark_container_id()
            except Exception as e:
                self.logger.error(f"Error getting docker id: {e}")
                raise ValueError(
                    "Cannot get docker id. Please run the container (san2patch-benchmark) first."
                )

        self.mode = mode
        self.LLMPatcher = LLMPatcher
        self.version = version
        self.aim_run = aim_run
        self.select_method = select_method
        self.temperature_setting = temperature_setting

        vuln_data_file = os.path.join(self.data_dir, "vuln", f"{self.vuln_id}.json")

        if not os.path.exists(vuln_data_file):
            self.logger.error(f"Vulnerability data file not found: {vuln_data_file}")

        with open(vuln_data_file, "r") as f:
            self.vuln_data = json.load(f)

        san_output_file = os.path.join(
            self.data_dir, "sanitizer", f"{self.vuln_id}.san"
        )

        if not os.path.exists(san_output_file):
            self.logger.error(f"Sanitizer output file not found: {san_output_file}")

        with open(san_output_file, "r", errors="ignore") as f:
            self.san_output = f.read()

        self.output_dir = os.path.join(self.data_dir, "output")

        self.package_name = self.vuln_data["subject"]

        self.experiment_name = experiment_name
        if self.experiment_name is not None:
            self.diff_dir = os.path.join(
                self.data_dir, f"gen_diff_{self.experiment_name}", self.vuln_id
            )
        else:
            self.diff_dir = os.path.join(self.data_dir, "gen_diff", self.vuln_id)

        if not os.path.exists(self.diff_dir):
            os.makedirs(self.diff_dir)

        self.repo_dir = os.path.join(
            self.data_dir, "repo", f"{self.package_name}_{self.vuln_id}"
        )
        self.copy_repo_dir = os.path.join(
            self.data_dir, "repo_copy", f"{self.package_name}_{self.vuln_id}"
        )

        if self.version in ["zeroshot", "cot", "no_context"]:
            self.context_mode = "line"
        else:
            self.context_mode = "ast"

        init_context(
            self.vuln_id,
            self.copy_repo_dir,
            self.context_mode,
            self.temperature_setting,
            self.docker_id,
        )

    def generate_patch(self):
        # Generate patch and save it to self.output_dir as filename {self.vuln_id}.diff
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.GENPATCH.value

        # Generate patch using LLM
        if self.version == "tot":
            patch_graph = generate_tot_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "ToTPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "mode": self.mode,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                    "select_method": self.select_method,
                }
            )
            res = FullPatchState(**res_json)

        elif self.version == "zeroshot":
            patch_graph = generate_zeroshot_patch_graph(self.LLMPatcher).with_config(
                {"run_name": "ZeroshotPatch"}
            )

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )

            res = ZeroshotPatchState(**res_json)

        elif self.version == "cot":
            patch_graph = generate_cot_patch_graph(self.LLMPatcher).with_config(
                {"run_name": "CoTPatch"}
            )

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )
            res = CoTPatchState(**res_json)

        elif self.version == "no_context":
            patch_graph = generate_no_context_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "NoContextPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )
            res = NoContextPatchState(**res_json)

        elif self.version == "no_comprehend":
            patch_graph = generate_no_comprehend_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "NoComprehendPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )
            res = NoComprehendPatchState(**res_json)

        elif self.version == "no_howtofix":
            patch_graph = generate_no_howtofix_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "NoHowToFixPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )
            res = NoHowToFixPatchState(**res_json)

        else:
            raise ValueError(f"Invalid version: {self.version}")

        return res

    def make_diff(self, try_cnt=0, stage=0):
        if not os.path.exists(self.copy_repo_dir):
            self.run_cmd(f"cp -r {self.repo_dir} {self.copy_repo_dir}")
            self.logger.info(f"Repo copy complete {self.copy_repo_dir}")

        self.run_cmd("git reset --hard", cwd=self.copy_repo_dir, quiet=True)

        self.diff_stage_dir = os.path.join(self.diff_dir, f"stage_{stage}_{try_cnt}")
        if not os.path.exists(self.diff_stage_dir):
            self.logger.info(f"create stage_{stage}_{try_cnt} {self.diff_stage_dir}")
            os.makedirs(self.diff_stage_dir)

        res = self.generate_patch()

        res_output = os.path.join(
            self.diff_stage_dir, f"{self.vuln_id}_graph_output.json"
        )
        with open(res_output, "w") as f:
            json.dump(res.model_dump(), f)

        return res

    class TestEvalRet(NamedTuple):
        ret_code: TestEvalRetCode
        err_msg: str

    def test_eval_patch(self) -> TestEvalRet:
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.EVAL.value

        stage_id = self.diff_stage_dir.split("/")[-1]

        pv = FinalTestValidator(
            self.vuln_data,
            stage_id,
            experiment_name=self.experiment_name,
            docker_id=self.docker_id,
        )

        # Setup docker container
        pv.setup()

        # Apply patch
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.PATCH.value

        patch_ret, patch_err_msg = pv.patch()
        if not patch_ret:
            return TestEvalRetCode.PATCH_FAILED, patch_err_msg

        # Build patched project
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.BUILD.value

        build_ret, build_err_msg = pv.build_test()
        if not build_ret:
            return TestEvalRetCode.BUILD_FAILED, build_err_msg

        # Test patched project using original crash input
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.VULN_TEST.value

        vuln_ret, vuln_err_msg = pv.vulnerability_test()
        if not vuln_ret:
            return TestEvalRetCode.VULN_FAILED, vuln_err_msg

        # Test patched project using functionality test
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.FUNC_TEST.value

        func_ret, func_err_msg = pv.functionality_test()
        if not func_ret:
            return TestEvalRetCode.FUNC_FAILED, func_err_msg

        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.END.value

        return TestEvalRetCode.SUCCESS, None


if __name__ == "__main__":
    pass
