import os

from langgraph.graph import StateGraph
from langsmith import traceable

from san2patch.consts import (
    FIX_BUILD_ERROR_RETRIES,
    GENPATCH_MAX_LINE,
    GENPATCH_MIN_LINE,
)
from san2patch.context import (
    San2PatchLogger,
    San2PatchTemperatureManager,
)
from san2patch.patching.graph.howtofix_graph import (
    HowToFixState,
)
from san2patch.patching.graph.runpatch_graph import (
    BuildTestState,
    FixBuildState,
    FunctionalityTestState,
    GenPatchState,
    PatchTestState,
    ValidatorState,
    VulnerabilityTestState,
    get_code_source,
)
from san2patch.patching.graph.wheretofix_graph import (
    LocationState,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.patch_prompts import (
    FixBuildErrorOnePrompt,
    FixErrorOneModel,
    PatchCodeModel,
    PatchCodePrompt,
)
from san2patch.patching.validator import FinalTestValidator
from san2patch.utils.enum import ExperimentResEnum
from san2patch.utils.reducers import *


# All
class RunPatchState(
    HowToFixState,
    GenPatchState,
    PatchTestState,
    BuildTestState,
    VulnerabilityTestState,
    FunctionalityTestState,
    ValidatorState,
): ...


# Input
class InputState(HowToFixState): ...


# Output
class OutputState(ValidatorState): ...


def generate_runpatch_graph(LLMPatcher: BaseLLMPatcher = GPT4oPatcher):
    graph_name = "runpatch"
    runpatch_builder = StateGraph(RunPatchState)
    llm_gen: BaseLLMPatcher = LLMPatcher(
        temperature=San2PatchTemperatureManager().genpatch
    )
    logger = San2PatchLogger().logger

    def get_original_code(state: RunPatchState, fix_location: LocationState):
        original_code, replace_line, _, _ = get_code_source(
            fix_location, state.package_location
        )

        # assert replace_line in original_code, f"replace_line: {replace_line} not in original_code: {original_code}"
        if replace_line not in original_code:
            original_code, replace_line, _, _ = get_code_source(
                fix_location,
                state.package_location,
                min_line=GENPATCH_MIN_LINE // 2,
                max_line=GENPATCH_MAX_LINE // 2,
            )

            if replace_line not in original_code:
                return original_code, original_code

        fixme_replace_line = (
            f"// FIXME: Crash {state.vuln_info_final.type}\n {replace_line}"
        )

        replace_code = original_code.replace(replace_line, fixme_replace_line)

        return original_code, replace_code

    def generate_patch(state: RunPatchState, genpatch_state: GenPatchState):
        # Clear all original code
        for loc in genpatch_state.fix_strategy.fix_location.locations:
            loc.original_code = ""

        # For each patch location, generate a new patch
        for _, loc in enumerate(genpatch_state.fix_strategy.fix_location.locations):
            try:
                original_code, replace_code = get_original_code(state, loc)
            except Exception as e:
                logger.error(
                    f"Error in getting original code: {e}. skipping fix location..."
                )
                continue

            loc.original_code = original_code

            patch: PatchCodeModel = ask(
                llm_gen,
                PatchCodePrompt,
                {
                    **state.model_dump(),
                    "original_function": replace_code,
                    "func_def": "",
                    "func_ret": "",
                },
            )

            loc.patched_code = patch.patched_code

    @traceable(type="validator")
    def test_patch(
        state: RunPatchState,
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

            original_lines = [line.strip() for line in original_function.splitlines()]
            patched_lines = [line.strip() for line in patched_function.splitlines()]

            if (
                original_lines[0] != patched_lines[0]
                or original_lines[-1] != patched_lines[-1]
            ):
                logger.warning(
                    "Original and patched codes do not match. Finding patched codes in the original code..."
                )

                try:
                    start_idx = original_lines.index(patched_lines[0])
                    end_idx = (
                        len(original_lines)
                        - 1
                        - original_lines[::-1].index(patched_lines[-1])
                    )

                    original_function = "\n".join(
                        original_function.splitlines()[start_idx : end_idx + 1]
                    )
                except ValueError:
                    logger.warning("Patched code not found in the original code.")

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
        if err_msg == None:
            err_msg = ""

        if not ret_code:
            pv.logger.warning("Patch failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.PATCH_FAILED.value
            )

        return PatchTestState(ret_code=ret_code, err_msg=err_msg)

    @traceable(type="validator")
    def test_build(
        state: RunPatchState,
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

            original_functions = [
                loc.original_code
                for loc in genpatch_state.fix_strategy.fix_location.locations
            ]
            patched_functions = [
                loc.patched_code
                for loc in genpatch_state.fix_strategy.fix_location.locations
            ]

            fix_build_state = FixBuildState(
                build_ret=ret_code,
                build_err_msg=err_msg,
                original_functions=original_functions,
                patched_functions=patched_functions,
            )

            fixed_res: FixErrorOneModel = ask(
                llm_gen, FixBuildErrorOnePrompt, fix_build_state
            )

            genpatch_state.fix_strategy.fix_location.locations[
                0
            ].patched_code = fixed_res.fixed_patched_function

        return BuildTestState(ret_code=ret_code, err_msg=err_msg)

    @traceable(type="validator")
    def test_vulnerability(
        state: RunPatchState,
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
        state: RunPatchState,
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

    def RunPatch(state: RunPatchState):
        pv = FinalTestValidator(
            state.vuln_data,
            state.diff_stage_dir.split("/")[-1],
            state.experiment_name,
        )

        genpatch_state = GenPatchState(fix_strategy=state.fix_strategy_final[0])

        generate_patch(state, genpatch_state)

        state.patch_success = [""]
        ret_patch = ret_build = ret_vuln = ret_func = None

        for retry_cnt in range(FIX_BUILD_ERROR_RETRIES):
            pv.logger.debug(f"Trying to patch {retry_cnt + 1} time...")
            ret_patch: PatchTestState = test_patch(state, genpatch_state, 0, pv)
            if not ret_patch.ret_code:
                break
            try:
                ret_build: BuildTestState = test_build(state, genpatch_state, 0, pv)
                if not ret_build.ret_code:
                    continue
            except Exception as e:
                logger.error(f"Error in build test: {e}")
                break
            ret_vuln: VulnerabilityTestState = test_vulnerability(
                state, genpatch_state, 0, pv
            )
            if not ret_vuln.ret_code:
                break
            ret_func: FunctionalityTestState = test_functionality(
                state, genpatch_state, 0, pv
            )
            if ret_func.ret_code:
                break

        pv.run_cmd("git reset --hard", cwd=state.package_location, quiet=True)

        return state

    runpatch_builder.add_node("runpatch_run_patch", RunPatch)
    runpatch_builder.add_node(
        "runpatch_end", lambda state: {"last_node": "runpatch_end"}
    )

    runpatch_builder.set_entry_point("runpatch_run_patch")
    runpatch_builder.set_finish_point("runpatch_end")

    runpatch_builder.add_edge("runpatch_run_patch", "runpatch_end")

    return runpatch_builder.compile()
