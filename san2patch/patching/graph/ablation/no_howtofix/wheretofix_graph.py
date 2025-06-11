from typing import Annotated

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
from san2patch.patching.graph.ablation.no_howtofix.comprehend_graph import (
    ComprehendState,
    LocationState,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.eval_prompts import EvalModel, WhereToFixEvalPrompt
from san2patch.patching.prompt.patch_prompts import (
    FaultLocalModel,
    SelectLocationPrompt,
)
from san2patch.utils.decorators import read_node_cache, write_node_cache
from san2patch.utils.jinja import trace_to_str
from san2patch.utils.reducers import *
from san2patch.utils.str import normalize_whitespace

TOOL_LIST = [
    get_code_by_file_with_lines,
    get_code_block_from_file_with_lines,
]


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


class FixStrategyState(BaseModel):
    fix_location: Annotated[FixLocationState, fixed_value] = FixLocationState()

    guideline: Annotated[str, fixed_value] = ""
    # example: Annotated[str, fixed_value] = ""
    description: Annotated[str, fixed_value] = ""
    rationale: Annotated[str, fixed_value] = ""

    score: Annotated[float, fixed_value] = 0.0
    confidence: Annotated[float, fixed_value] = 0.0
    reliability_score: Annotated[float, fixed_value] = 0.0
    eval_rationale: Annotated[str, fixed_value] = ""


class HowToFixFinalState(BaseModel):
    fix_strategy_final: Annotated[list[FixStrategyState], fixed_value] = []


# All
class WhereToFixState(
    ComprehendState,
    LocationCandidatesState,
    WhereToFixBranchState,
    WhereToFixFinalState,
    HowToFixFinalState,
): ...


# Input
class InputState(ComprehendState): ...


# Output
class OutputState(HowToFixFinalState): ...


def get_code_line(file_name, start, end, src_dir):
    cm = San2PatchContextManager("C", src_dir=src_dir)
    # code_line = cm.get_code_by_file_with_lines(file_name, int(start), int(end))
    try:
        code_line = cm.get_code_block(file_name, int(start), 5, 20)
    except:
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
    graph_name = "wheretofix"
    wheretofix_builder = StateGraph(WhereToFixState)
    temperature = San2PatchTemperatureManager()
    llm: BaseLLMPatcher = LLMPatcher(temperature=temperature.default)
    llm_branch: BaseLLMPatcher = LLMPatcher(temperature=temperature.branch)
    logger = San2PatchLogger().logger

    def prepare_candidates(state: WhereToFixState, thread: list[BaseMessage]):
        for trace in state.crash_stack_trace:
            state.location_candidates.append(
                LocationCandidateState(**trace.model_dump(), type="crash")
            )

        for trace in state.memory_allocate_stack_trace:
            state.location_candidates.append(
                LocationCandidateState(**trace.model_dump(), type="memory_allocate")
            )

        for trace in state.memory_free_stack_trace:
            state.location_candidates.append(
                LocationCandidateState(**trace.model_dump(), type="memory_free")
            )

    def get_fix_location_candidates(state: WhereToFixState, thread: list[BaseMessage]):
        crash_stack_trace_bak = state.crash_stack_trace.copy()
        memory_allocate_stack_trace_bak = state.memory_allocate_stack_trace.copy()
        memory_free_stack_trace_bak = state.memory_free_stack_trace.copy()

        state.crash_stack_trace = [
            trace_to_str(trace) for trace in state.crash_stack_trace
        ]
        state.memory_allocate_stack_trace = [
            trace_to_str(trace) for trace in state.memory_allocate_stack_trace
        ]
        state.memory_free_stack_trace = [
            trace_to_str(trace) for trace in state.memory_free_stack_trace
        ]

        all_stack_traces = (
            state.crash_stack_trace
            + state.memory_allocate_stack_trace
            + state.memory_free_stack_trace
        )

        for _ in range(1, branch_num + 1):
            # Ask one by one
            try:
                fault_local: FaultLocalModel = ask(
                    llm_branch, SelectLocationPrompt, state
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
            selected_stack_trace = fault_local.selected_stack_trace
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

            # Remove selected stack trace from stack traces
            for stack_trace in selected_stack_trace:
                if stack_trace in state.crash_stack_trace:
                    state.crash_stack_trace.remove(stack_trace)
                if stack_trace in state.memory_allocate_stack_trace:
                    state.memory_allocate_stack_trace.remove(stack_trace)
                if stack_trace in state.memory_free_stack_trace:
                    state.memory_free_stack_trace.remove(stack_trace)
                if stack_trace in all_stack_traces:
                    all_stack_traces.remove(stack_trace)
            if len(all_stack_traces) == 0:
                break

        # Restore the stack traces
        state.crash_stack_trace = crash_stack_trace_bak
        state.memory_allocate_stack_trace = memory_allocate_stack_trace_bak
        state.memory_free_stack_trace = memory_free_stack_trace_bak

    @read_node_cache(
        graph_name=graph_name, cache_model=OutputState, mock=True, enabled=cached
    )
    def BranchWhereToFix(state: WhereToFixState):
        thread = []

        prepare_candidates(state, thread)
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
    def SelectWhereToFix(state: WhereToFixState):
        select_wheretofix(state)
        return state

    @write_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    def MakeDummyHowToFix(state: WhereToFixState):
        for fix_location in state.fix_location_final:
            state.fix_strategy_final.append(
                FixStrategyState(
                    fix_location=fix_location,
                )
            )
        return state

    wheretofix_builder.add_node("branch_wheretofix", BranchWhereToFix)
    wheretofix_builder.add_node("select_wheretofix", SelectWhereToFix)
    wheretofix_builder.add_node("make_dummy_howtofix", MakeDummyHowToFix)

    wheretofix_builder.set_entry_point("branch_wheretofix")
    wheretofix_builder.set_finish_point("make_dummy_howtofix")

    wheretofix_builder.add_edge("branch_wheretofix", "select_wheretofix")
    wheretofix_builder.add_edge("select_wheretofix", "make_dummy_howtofix")
    return wheretofix_builder.compile()
