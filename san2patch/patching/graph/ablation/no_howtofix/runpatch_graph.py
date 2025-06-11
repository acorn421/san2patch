import os
from functools import partial
from typing import Annotated

from langgraph.graph import StateGraph
from langsmith import traceable
from pydantic import BaseModel

from san2patch.consts import (
    FIX_BUILD_ERROR_RETRIES,
    GENPATCH_MAX_LINE,
    GENPATCH_MIN_LINE,
)
from san2patch.context import (
    San2PatchContextManager,
    San2PatchLogger,
    San2PatchTemperatureManager,
)
from san2patch.patching.graph.ablation.no_howtofix.wheretofix_graph import (
    FixStrategyState,
    LocationState,
    WhereToFixState,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.patch_prompts import (
    FixBuildErrorPrompt,
    FixErrorModel,
    PatchCodeBranchPrompt,
)
from san2patch.patching.validator import FinalTestValidator
from san2patch.utils.enum import ExperimentResEnum
from san2patch.utils.reducers import *


class GenPatchState(BaseModel):
    fix_strategy: Annotated[FixStrategyState, fixed_value] = FixStrategyState()
    patch_result: Annotated[str, fixed_value] = ""

    def validate_self(self):
        for loc in self.fix_strategy.fix_location.locations:
            if not loc.original_code:
                raise ValueError("Original code is empty")


class GenPatchCandidateState(BaseModel):
    genpatch_candidate: Annotated[list[GenPatchState], fixed_value] = []


class RunResultState(BaseModel):
    ret_code: Annotated[bool, fixed_value] = False
    err_msg: Annotated[str | bool, fixed_value] = ""


class PatchTestState(RunResultState): ...


class BuildTestState(RunResultState): ...


class VulnerabilityTestState(RunResultState): ...


class FunctionalityTestState(RunResultState): ...


class ValidatorState(BaseModel):
    vuln_data: Annotated[dict, fixed_value]
    patch_success: Annotated[list[str], fixed_value]


class FixBuildState(BaseModel):
    build_ret: Annotated[bool, fixed_value] = False
    build_err_msg: Annotated[str, fixed_value] = ""
    original_functions: Annotated[list[str], fixed_value] = []
    patched_functions: Annotated[list[str], fixed_value] = []


# All
class RunPatchState(
    WhereToFixState,
    GenPatchState,
    GenPatchCandidateState,
    PatchTestState,
    BuildTestState,
    VulnerabilityTestState,
    FunctionalityTestState,
    ValidatorState,
): ...


# Input
class InputState(WhereToFixState): ...


# Output
class OutputState(GenPatchCandidateState, ValidatorState): ...


def get_code_source(
    fix_location: LocationState,
    src_dir,
    min_line=GENPATCH_MIN_LINE,
    max_line=GENPATCH_MAX_LINE,
):
    cm = San2PatchContextManager("C", src_dir=src_dir)
    code_context = cm.get_code_context(
        file_name=fix_location.file_name,
        line=int(fix_location.fix_line),
        min_line=min_line,
        max_line=max_line,
        sibling=False,
    )
    code_block = code_context.code
    code_line = cm.get_code_lines(
        file_name=fix_location.file_name,
        line_start=int(fix_location.fix_line) - 2,
        line_end=int(fix_location.fix_line) + 2,
    )

    return code_block, code_line, code_context.func_def, code_context.func_ret


def generate_runpatch_graph(
    LLMPatcher: BaseLLMPatcher = GPT4oPatcher, branch_num: int = 3
):
    graph_name = "runpatch"
    runpatch_builder = StateGraph(RunPatchState)
    temperature = San2PatchTemperatureManager()
    llm: BaseLLMPatcher = LLMPatcher(temperature=temperature.default)
    llm_gen: BaseLLMPatcher = LLMPatcher(temperature=temperature.genpatch)
    logger = San2PatchLogger().logger

    def get_original_code(state: RunPatchState, fix_location: LocationState):
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

        fixme_replace_line = (
            f"// FIXME: Crash {state.vuln_info_final.type}\n {replace_line}"
        )

        replace_code = original_code.replace(replace_line, fixme_replace_line)

        return original_code, replace_code, func_def, func_ret

    def branch_generate_patch(state: RunPatchState, genpatch_state: GenPatchState):
        # Clear all original code
        for loc in genpatch_state.fix_strategy.fix_location.locations:
            loc.original_code = ""

        # Create new mock genpatch states
        new_genpatch_states = [
            genpatch_state.model_copy(deep=True) for _ in range(branch_num)
        ]

        # For each patch location, generate a new patch
        for loc_idx, loc in enumerate(
            genpatch_state.fix_strategy.fix_location.locations
        ):
            try:
                original_code, replace_code, func_def, func_ret = get_original_code(
                    state, loc
                )
            except Exception as e:
                logger.error(
                    f"Error in getting original code: {e}. skipping fix location..."
                )
                continue

            for patch_idx in range(branch_num):
                loc = new_genpatch_states[
                    patch_idx
                ].fix_strategy.fix_location.locations[loc_idx]
                loc.original_code = original_code
                loc.func_def = func_def
                loc.func_ret = func_ret

            prompt_cls = partial(PatchCodeBranchPrompt, branch_num=branch_num)

            try:
                patches = ask(
                    llm_gen,
                    prompt_cls,
                    {
                        **state.model_dump(),
                        "fix_strategy": genpatch_state.fix_strategy,
                        "original_function": replace_code,
                        "func_def": func_def,
                        "func_ret": func_ret,
                    },
                )
            except Exception as e:
                logger.warning(
                    f"Error in generating patch: {e}. Set patched code to original code."
                )
                for patch_idx in range(branch_num):
                    new_genpatch_states[patch_idx].fix_strategy.fix_location.locations[
                        loc_idx
                    ].patched_code = (
                        new_genpatch_states[patch_idx]
                        .fix_strategy.fix_location.locations[loc_idx]
                        .original_code
                    )
            else:
                for patch_idx in range(branch_num):
                    new_genpatch_states[patch_idx].fix_strategy.fix_location.locations[
                        loc_idx
                    ].patched_code = patches.__getattribute__(
                        f"patched_code_{patch_idx + 1}"
                    )

        # Remove invalid genpatch states
        final_genpatch_states = []
        for new_state in new_genpatch_states:
            try:
                new_state.validate_self()
                final_genpatch_states.append(new_state)
            except Exception as e:
                logger.error(
                    f"Error in validating genpatch state: {e}. skipping genpatch..."
                )
                continue

        return final_genpatch_states

    def genpatch_per_strategy(state: RunPatchState, fix_strategy: FixStrategyState):
        genpatch_state = GenPatchState(fix_strategy=fix_strategy)
        branched_genpatch_states = branch_generate_patch(state, genpatch_state)

        state.genpatch_candidate.extend(branched_genpatch_states)

        return branched_genpatch_states

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

            # Post-process for small bug in the code
            if San2PatchContextManager().context_mode == "line":
                original_lines = [
                    line.strip() for line in original_function.splitlines()
                ]
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
            else:
                temp_patched_function = patched_function.strip()
                if (original_function.count("{") == original_function.count("}")) and (
                    patched_function.count("{") == patched_function.count("}")
                ):
                    if original_function[0] == "{" and temp_patched_function[0] != "{":
                        patched_function = "{\n" + patched_function + "\n}"

            # patched_function = patched_function.strip()
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

            try:
                fixed_res: FixErrorModel = ask(
                    llm, FixBuildErrorPrompt, fix_build_state
                )
            except Exception as e:
                logger.warning(f"Error in fixing build error: {e}. skipping...")
            else:
                for idx, patched_function in enumerate(
                    fixed_res.fixed_patched_functions
                ):
                    genpatch_state.fix_strategy.fix_location.locations[
                        idx
                    ].patched_code = patched_function

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

        for fix_strategy in state.fix_strategy_final:
            branched_genpatch_states: list[GenPatchState] = genpatch_per_strategy(
                state, fix_strategy
            )

            start_id = len(state.patch_success)
            state.patch_success.extend([""] * len(branched_genpatch_states))
            ret_patch = ret_build = ret_vuln = ret_func = None

            for _id, genpatch_state in enumerate(branched_genpatch_states):
                genpatch_id = start_id + _id
                try:
                    genpatch_state.validate_self()
                except Exception as e:
                    logger.error(
                        f"Error in validating genpatch state: {e}. skipping genpatch..."
                    )
                    continue

                for retry_cnt in range(FIX_BUILD_ERROR_RETRIES):
                    pv.logger.debug(f"Trying to patch {retry_cnt + 1} time...")
                    ret_patch: PatchTestState = test_patch(
                        state, genpatch_state, genpatch_id, pv
                    )
                    if not ret_patch.ret_code:
                        break
                    try:
                        ret_build: BuildTestState = test_build(
                            state, genpatch_state, genpatch_id, pv
                        )
                        if not ret_build.ret_code:
                            continue
                    except Exception as e:
                        logger.error(f"Error in build test: {e}")
                        break
                    ret_vuln: VulnerabilityTestState = test_vulnerability(
                        state, genpatch_state, genpatch_id, pv
                    )
                    if not ret_vuln.ret_code:
                        break
                    ret_func: FunctionalityTestState = test_functionality(
                        state, genpatch_state, genpatch_id, pv
                    )
                    if ret_func.ret_code:
                        break
                if ret_func is not None and ret_func.ret_code:
                    break
            if ret_func is not None and ret_func.ret_code:
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
