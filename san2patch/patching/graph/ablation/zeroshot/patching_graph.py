import os

from langgraph.graph import StateGraph
from langsmith import traceable

from san2patch.consts import GENPATCH_MAX_LINE, GENPATCH_MIN_LINE
from san2patch.context import (
    San2PatchLogger,
    San2PatchTemperatureManager,
)
from san2patch.patching.graph.comprehend_graph import LocationState, VDState
from san2patch.patching.graph.runpatch_graph import (
    BuildTestState,
    FunctionalityTestState,
    GenPatchState,
    PatchTestState,
    ValidatorState,
    VulnerabilityTestState,
    get_code_source,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.patch_prompts import (
    ZeroshotFaultLocalModel,
    ZeroshotPatchCodeModel,
    ZeroshotPatchCodePrompt,
    ZeroshotSelectLocationPrompt,
)
from san2patch.patching.validator import FinalTestValidator
from san2patch.utils.enum import ExperimentResEnum
from san2patch.utils.reducers import *


class ZeroshotPatchState(VDState, GenPatchState, ValidatorState): ...


class InputState(VDState): ...


class OutputState(GenPatchState, ValidatorState): ...


logger = San2PatchLogger().logger


def generate_zeroshot_patch_graph(LLMPatcher: BaseLLMPatcher = GPT4oPatcher):
    graph_name = "zeroshot"
    patch_builder = StateGraph(ZeroshotPatchState)
    llm: BaseLLMPatcher = LLMPatcher(temperature=San2PatchTemperatureManager().default)

    def WhereToFix(state: ZeroshotPatchState):
        for retry_cnt in range(3):
            fix_loc: ZeroshotFaultLocalModel = ask(
                llm, ZeroshotSelectLocationPrompt, state
            )

            try:
                fix_loc.validate_self(check_code=True)
            except Exception as e:
                logger.warning(f"Error in fault_local: {e}. trying to fix the filename")
                try:
                    fix_loc.fix_filename()
                except Exception as e:
                    logger.warning(
                        f"Error in fault_local: {e}. Re-ask the question {retry_cnt + 1}"
                    )
                    continue
                else:
                    break
            else:
                break

        state.fix_strategy.fix_location.locations = [
            LocationState(
                file_name=loc.fix_file_name,
                fix_line=loc.fix_line,
                start_line=loc.fix_start_line,
                end_line=loc.fix_end_line,
            )
            for loc in fix_loc.fix_locations
        ]

        return state

    def get_original_code(state: ZeroshotPatchState, fix_location: LocationState):
        original_code, replace_line, func_def, func_ret = get_code_source(
            fix_location, state.package_location
        )

        # assert replace_line in original_code, f"replace_line: {replace_line} not in original_code: {original_code}"
        if replace_line not in original_code:
            original_code, replace_line, func_def, func_ret = get_code_source(
                fix_location,
                state.package_location,
                min_line=GENPATCH_MIN_LINE // 2,
                max_line=GENPATCH_MAX_LINE // 2,
            )

            if replace_line not in original_code:
                return original_code, original_code, func_def, func_ret

        fixme_replace_line = f"// FIXME: Crash\n {replace_line}"

        replace_code = original_code.replace(replace_line, fixme_replace_line)

        return original_code, replace_code, func_def, func_ret

    def generate_patch(state: ZeroshotPatchState, genpatch_state: GenPatchState):
        # Clear all original code
        for loc in genpatch_state.fix_strategy.fix_location.locations:
            loc.original_code = ""

        # For each patch location, generate a new patch
        for _, loc in enumerate(genpatch_state.fix_strategy.fix_location.locations):
            try:
                original_code, replace_code, func_def, func_ret = get_original_code(
                    state, loc
                )
            except Exception as e:
                logger.error(
                    f"Error in getting original code: {e}. skipping fix location..."
                )
                continue

            loc.original_code = original_code

            patch: ZeroshotPatchCodeModel = ask(
                llm,
                ZeroshotPatchCodePrompt,
                {
                    **state.model_dump(),
                    "original_function": replace_code,
                    "func_def": func_def,
                    "func_ret": func_ret,
                },
            )

            loc.patched_code = patch.patched_code

    def GenPatch(state: ZeroshotPatchState):
        generate_patch(state, state)
        return state

    @traceable(type="validator")
    def test_patch(
        state: ZeroshotPatchState,
        genpatch_state: GenPatchState,
        genpatch_id: int,
        pv: FinalTestValidator,
    ) -> PatchTestState:
        # Rest repo dir
        pv.run_cmd("git reset --hard", cwd=state.package_location, quiet=True)

        # Post-process for small bug in the code
        for fix_loc in genpatch_state.fix_strategy.fix_location.locations:
            file_name = fix_loc.file_name
            original_function = fix_loc.original_code
            patched_function = fix_loc.patched_code

            if file_name[0] == "/" or file_name[0] == "\\":
                file_name = file_name[1:]

            with open(os.path.join(state.package_location, file_name), "r") as f:
                source_code = f.read()

            patched_code = ""
            if source_code.find(original_function):
                patched_code = source_code.replace(original_function, patched_function)

            with open(os.path.join(state.package_location, file_name), "w") as f:
                f.write(patched_code)

        # Generate patch using "git diff"
        patch_diff_file = os.path.join(state.diff_stage_dir, state.vuln_id)
        pv.run_cmd(
            f"git diff --patch > {patch_diff_file}_{genpatch_id}.diff",
            cwd=state.package_location,
        )
        pv.run_cmd(
            f"git diff --patch > {patch_diff_file}.diff",
            cwd=state.package_location,
        )

        # Setup Patch Validator
        pv.setup()

        # Apply patch
        ret_code, err_msg = pv.patch()
        if err_msg is None:
            err_msg = ""

        if not ret_code:
            pv.logger.warning("Patch failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.PATCH_FAILED.value
            )

        return PatchTestState(ret_code=ret_code, err_msg=err_msg)

    @traceable(type="validator")
    def test_build(
        state: ZeroshotPatchState,
        genpatch_state: GenPatchState,
        genpatch_id: int,
        pv: FinalTestValidator,
    ) -> BuildTestState:
        ret_code, err_msg = pv.build_test()
        if err_msg is None:
            err_msg = ""

        if not ret_code:
            pv.logger.warning("Build test failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.BUILD_FAILED.value
            )
        else:
            pv.logger.success("Build test passed.")

        return BuildTestState(ret_code=ret_code, err_msg=err_msg)

    @traceable(type="validator")
    def test_vulnerability(
        state: ZeroshotPatchState,
        genpatch_state: GenPatchState,
        genpatch_id: int,
        pv: FinalTestValidator,
    ) -> VulnerabilityTestState:
        ret_code, err_msg = pv.vulnerability_test()
        if err_msg is None:
            err_msg = ""

        if not ret_code:
            pv.logger.warning("Vulnerability test failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.VULN_FAILED.value
            )

        return VulnerabilityTestState(ret_code=ret_code, err_msg=err_msg)

    @traceable(type="validator")
    def test_functionality(
        state: ZeroshotPatchState,
        genpatch_state: GenPatchState,
        genpatch_id: int,
        pv: FinalTestValidator,
    ) -> FunctionalityTestState:
        ret_code, err_msg = pv.functionality_test()
        if err_msg is None:
            err_msg = ""

        if not ret_code:
            pv.logger.warning("Functionality test failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.FUNC_FAILED.value
            )
        else:
            pv.logger.critical(
                f"Congratulations! You have successfully patched the {state.vuln_id} vulnerability!"
            )
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.SUCCESS.value
            )

        return FunctionalityTestState(ret_code=ret_code, err_msg=err_msg)

    def RunPatch(state: ZeroshotPatchState):
        pv = FinalTestValidator(
            state.vuln_data,
            state.diff_stage_dir.split("/")[-1],
            state.experiment_name,
        )

        # GenPatch(state)

        state.patch_success = [""]
        ret_patch = ret_build = ret_vuln = ret_func = None

        ret_patch: PatchTestState = test_patch(state, state, 0, pv)
        if not ret_patch.ret_code:
            return state
        ret_build: BuildTestState = test_build(state, state, 0, pv)
        if not ret_build.ret_code:
            return state
        ret_vuln: VulnerabilityTestState = test_vulnerability(state, state, 0, pv)
        if not ret_vuln.ret_code:
            return state
        ret_func: FunctionalityTestState = test_functionality(state, state, 0, pv)

        return state

    patch_builder.add_node("wheretofix", WhereToFix)
    patch_builder.add_node("genpatch", GenPatch)
    patch_builder.add_node("runpatch", RunPatch)

    patch_builder.set_entry_point("wheretofix")
    patch_builder.set_finish_point("runpatch")

    patch_builder.add_edge("wheretofix", "genpatch")
    patch_builder.add_edge("genpatch", "runpatch")

    return patch_builder.compile()
