from typing import Annotated, Literal

import numpy as np
from langchain_core.messages import BaseMessage
from langgraph.graph import StateGraph
from pydantic import BaseModel

from san2patch.consts import SCORE_ALPHA
from san2patch.context import (
    San2PatchContextManager,
    San2PatchLogger,
    San2PatchTemperatureManager,
)
from san2patch.patching.context.code_context import (
    get_code_block_from_file_with_lines,
    get_code_by_file_with_lines,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.eval_prompts import EvalModel, WhereToFixEvalPrompt
from san2patch.patching.prompt.patch_prompts import (
    FaultLocalModel,
    SelectLocationNoComprehendPrompt,
)
from san2patch.utils.decorators import read_node_cache, write_node_cache
from san2patch.utils.reducers import *
from san2patch.utils.str import normalize_whitespace

TOOL_LIST = [
    get_code_by_file_with_lines,
    get_code_block_from_file_with_lines,
]


class PackageState(BaseModel):
    package_language: Annotated[Literal["C"], fixed_value] = "C"
    package_name: Annotated[str, fixed_value] = ""
    package_location: Annotated[str, fixed_value] = ""


class VulnerabilityState(BaseModel):
    vuln_id: Annotated[str, fixed_value] = ""
    sanitizer_output: Annotated[str, fixed_value] = ""


class ConfigState(BaseModel):
    mode: Annotated[str, fixed_value] = ""
    diff_stage_dir: Annotated[str, fixed_value] = ""
    experiment_name: Annotated[str, fixed_value] = ""
    select_method: Annotated[Literal["greedy", "sample"], fixed_value] = "sample"


class VDState(PackageState, VulnerabilityState, ConfigState):
    last_node: Annotated[str, fixed_value] = ""


class LocationState(BaseModel):
    file_name: Annotated[str, fixed_value] = ""
    fix_line: Annotated[int, fixed_value] = 0
    start_line: Annotated[int, fixed_value] = 0
    end_line: Annotated[int, fixed_value] = 0

    function_name: Annotated[str, fixed_value] = ""

    code: Annotated[str, fixed_value] = ""
    original_code: Annotated[str, fixed_value] = ""
    patched_code: Annotated[str, fixed_value] = ""

    func_def: Annotated[str, fixed_value] = ""
    func_ret: Annotated[list[str], fixed_value] = []

    def validate_location(self):
        if self.start_line <= 0 or self.end_line <= 0:
            raise ValueError(
                "Invalid location: start_line and end_line must be positive integers"
            )

        if self.start_line > self.end_line:
            raise ValueError(
                "Invalid location: start_line must be less than or equal to end_line"
            )


class VulnInfoState(BaseModel):
    type: Annotated[str, fixed_value] = ""
    root_cause: Annotated[str, fixed_value] = ""
    comprehension: Annotated[str, fixed_value] = ""
    rationale: Annotated[str, fixed_value] = ""


class DummyComprehendFinalState(BaseModel):
    vuln_info_final: Annotated[VulnInfoState, fixed_value] = VulnInfoState()


# Where-To-Fix core state
class FixLocationState(BaseModel):
    locations: Annotated[list[LocationState], fixed_value] = []
    rationale: Annotated[str, fixed_value] = ""

    # evaluation
    score: Annotated[float, fixed_value] = 0.0
    confidence: Annotated[float, fixed_value] = 0.0
    reliability_score: Annotated[float, fixed_value] = 0.0
    eval_rationale: Annotated[str, fixed_value] = ""

    def __hash__(self):
        _set = set(
            [f"{l.file_name}:{l.start_line}:{l.end_line}" for l in self.locations]
        )
        return hash(tuple(_set))


class LocationCandidateState(LocationState):
    type: Annotated[str, fixed_value] = ""


class LocationCandidatesState(BaseModel):
    location_candidates: Annotated[list[LocationCandidateState], fixed_value] = []


class WhereToFixBranchState(BaseModel):
    fix_location_candidates: Annotated[list[FixLocationState], reduce_list] = []


class WhereToFixFinalState(BaseModel):
    fix_location_final: Annotated[list[FixLocationState], fixed_value] = []


# All
class WhereToFixState(
    VDState,
    DummyComprehendFinalState,
    LocationCandidatesState,
    WhereToFixBranchState,
    WhereToFixFinalState,
): ...


# Input
class InputState(VDState): ...


# Output
class OutputState(WhereToFixFinalState): ...


def get_code_line(file_name, start, end, src_dir):
    cm = San2PatchContextManager("C", src_dir=src_dir)
    # code_line = cm.get_code_by_file_with_lines(file_name, int(start), int(end))
    try:
        code_line = cm.get_code_block(file_name, int(start), 5, 20)
    except Exception:
        code_line = (
            f"Failed to retrieve code block from '{file_name}' at line {start}. "
            f"Possible issue: invalid filename, line number, or file access."
        )
    return code_line


def rel_line_number(code_context: str, code_line: str) -> int:
    code_context = [normalize_whitespace(code) for code in code_context.split("\n")]
    code_line = normalize_whitespace(code_line)
    total_lines = len(code_context)

    try:
        return code_context.index(code_line) - total_lines
    except ValueError:
        print(
            f"Cannot find the rel line number: context: {code_context} code: {code_line}"
        )
        return 1


def generate_wheretofix_graph(
    LLMPatcher: BaseLLMPatcher = GPT4oPatcher,
    branch_num: int = 5,
    select_num: int = 3,
    cached: bool = False,
):
    graph_name = "no_comprehend_wheretofix"
    wheretofix_builder = StateGraph(WhereToFixState)
    temperature = San2PatchTemperatureManager()
    llm: BaseLLMPatcher = LLMPatcher(temperature=temperature.default)
    llm_branch: BaseLLMPatcher = LLMPatcher(temperature=temperature.branch)
    logger = San2PatchLogger().logger

    def get_fix_location_candidates(state: WhereToFixState, thread: list[BaseMessage]):
        for _ in range(1, branch_num + 1):
            # Ask one by one
            try:
                fault_local: FaultLocalModel = ask(
                    llm_branch, SelectLocationNoComprehendPrompt, state
                )
            except Exception as e:
                logger.warning(f"Cannot get fix location using llm: {e}. Skipping.")
                continue

            try:
                fault_local.validate_self(check_code=True)
            except Exception as e:
                logger.warning(f"Error in fault_local: {e}. trying to fix the filename")
                try:
                    fault_local.fix_filename()
                except Exception as e:
                    logger.warning(f"Error in fault_local: {e}")
                    continue

            # Parse the results
            fix_loc = fault_local.fix_locations
            rationale = fault_local.fix_location_rationale

            fix_location = FixLocationState()

            for loc in fix_loc:
                code = get_code_line(
                    loc.fix_file_name,
                    loc.fix_line,
                    loc.fix_line,
                    state.package_location,
                )

                fix_location.locations.append(
                    LocationState(
                        file_name=loc.fix_file_name,
                        fix_line=loc.fix_line,
                        start_line=loc.fix_start_line,
                        end_line=loc.fix_end_line,
                        code=code,
                    )
                )
            fix_location.rationale = rationale

            # Add to candidates
            state.fix_location_candidates.append(fix_location)

    @read_node_cache(
        graph_name=graph_name, cache_model=OutputState, mock=True, enabled=cached
    )
    def BranchWhereToFix(state: WhereToFixState):
        thread = []

        get_fix_location_candidates(state, thread)

        return state

    def eval_wheretofix(state: WhereToFixState, loc_state: FixLocationState):
        try:
            eval_res: EvalModel = ask(
                llm, WhereToFixEvalPrompt, {**state.model_dump(), "fix_loc": loc_state}
            )
        except Exception as e:
            logger.warning(f"Failed to evaluate wheretofix. Set minimum score. {e}")
            loc_state.score = 0.1
            loc_state.confidence = 0.1
            loc_state.reliability_score = loc_state.score * (
                1 + SCORE_ALPHA * loc_state.confidence
            )
            loc_state.eval_rationale = ""
        else:
            loc_state.score = eval_res.numeric_score
            loc_state.confidence = eval_res.confidence
            loc_state.reliability_score = loc_state.score * (
                1 + SCORE_ALPHA * loc_state.confidence
            )
            loc_state.eval_rationale = eval_res.rationale

        return loc_state

    def select_wheretofix(state: WhereToFixState):
        for loc_state in state.fix_location_candidates:
            eval_wheretofix(state, loc_state)

        # Aggregate same fix location
        fix_loc_dict: dict[str, FixLocationState] = {}
        for fix_location in state.fix_location_candidates:
            loc_id = hash(fix_location)
            if loc_id not in fix_loc_dict:
                fix_loc_dict[loc_id] = fix_location
            else:
                fix_loc_dict[loc_id].reliability_score += fix_location.reliability_score

        dedeup_fix_locations = list(fix_loc_dict.values())

        # Select top select_num wheretofix results
        scores = [loc.reliability_score for loc in dedeup_fix_locations]
        select_size = min(select_num, len(dedeup_fix_locations))
        ids = list(range(len(dedeup_fix_locations)))
        if state.select_method == "greedy":
            select_ids = sorted(ids, key=lambda x: scores[x], reverse=True)[
                :select_size
            ]
        elif state.select_method == "sample":
            ps = np.array(scores) / sum(scores)
            select_ids = np.random.choice(
                ids,
                size=select_size,
                p=ps,
                replace=False,
            ).tolist()
            ps = np.array(scores) / sum(scores)
            select_ids = np.random.choice(
                ids, size=select_size, p=ps, replace=False
            ).tolist()

        state.fix_location_final = [dedeup_fix_locations[i] for i in select_ids]

    @read_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    @write_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    def SelectWhereToFix(state: WhereToFixState):
        select_wheretofix(state)
        return state

    wheretofix_builder.add_node("branch_wheretofix", BranchWhereToFix)
    wheretofix_builder.add_node("select_wheretofix", SelectWhereToFix)

    wheretofix_builder.set_entry_point("branch_wheretofix")
    wheretofix_builder.set_finish_point("select_wheretofix")

    wheretofix_builder.add_edge("branch_wheretofix", "select_wheretofix")

    return wheretofix_builder.compile()
