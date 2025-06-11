from typing import Annotated, Literal, Type

from langchain_core.messages import BaseMessage
from langgraph.graph import StateGraph
from pydantic import BaseModel

from san2patch.context import (
    San2PatchContextManager,
    San2PatchLogger,
    San2PatchTemperatureManager,
)
from san2patch.patching.context.code_context import (
    get_code_block_from_file_with_lines,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.patch_prompts import (
    ComprehendAggregateModel,
    ComprehendAggregatePrompt,
    FilterStackTraceCompPrompt,
    GetStackTraceCompPrompt,
    RootCauseModel,
    RootCausePrompt,
    StackTraceModel,
    VulnDescModel,
    VulnDescPrompt,
    VulnTypeModel,
    VulnTypePrompt,
    WrongStackTracePrompt,
)
from san2patch.types import OutputT
from san2patch.utils.decorators import read_node_cache, write_node_cache
from san2patch.utils.reducers import *
from san2patch.utils.str import normalize_whitespace


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


# Location core state
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


class StackTraceState(BaseModel):
    crash_stack_trace: Annotated[list[LocationState], fixed_value] = []
    memory_allocate_stack_trace: Annotated[list[LocationState], fixed_value] = []
    memory_free_stack_trace: Annotated[list[LocationState], fixed_value] = []


# Vuln comprehend core state
class VulnInfoState(BaseModel):
    type: Annotated[str, fixed_value] = ""
    root_cause: Annotated[str, fixed_value] = ""
    comprehension: Annotated[str, fixed_value] = ""
    rationale: Annotated[str, fixed_value] = ""


class ComprehendBranchState(BaseModel):
    vuln_info_candidates: Annotated[list[VulnInfoState], reduce_list] = []


class ComprehendCoTState(BaseModel):
    vuln_info: Annotated[VulnInfoState, fixed_value] = VulnInfoState()


class CopmrehendFinalState(BaseModel):
    vuln_info_final: Annotated[VulnInfoState, fixed_value] = VulnInfoState()


# All
class ComprehendState(
    VDState,
    StackTraceState,
    CopmrehendFinalState,
    ComprehendBranchState,
    ComprehendCoTState,
): ...


# Input
class InputState(VDState): ...


# Output
class OutputState(CopmrehendFinalState, StackTraceState): ...


TOOL_LIST = [
    get_code_block_from_file_with_lines,
]


def generate_comprehend_graph(
    LLMPatcher: Type[BaseLLMPatcher[OutputT]] = GPT4oPatcher,
    consistency_num: int = 3,
    cached: bool = False,
):
    graph_name = "comprehend"
    comprehend_builder = StateGraph(ComprehendState)
    temperature = San2PatchTemperatureManager()
    llm: BaseLLMPatcher = LLMPatcher(temperature=temperature.default)
    llm_branch: BaseLLMPatcher = LLMPatcher(temperature=temperature.branch)
    logger = San2PatchLogger().logger

    def update_stack_trace(state: ComprehendState, stack_trace: StackTraceModel):
        def is_valid_trace(trace: str) -> bool:
            try:
                if int(trace.split("@")[1]) and len(trace.split("@")) == 3:
                    return True
                else:
                    return False
            except Exception:
                return False

        state.crash_stack_trace = [
            LocationState(
                file_name=trace.split("@")[0],
                fix_line=trace.split("@")[1],
                start_line=trace.split("@")[1],
                end_line=trace.split("@")[1],
                function_name=trace.split("@")[2],
            )
            for trace in stack_trace.crash_stack_trace
            if is_valid_trace(trace)
        ]
        state.memory_allocate_stack_trace = [
            LocationState(
                file_name=trace.split("@")[0],
                fix_line=trace.split("@")[1],
                start_line=trace.split("@")[1],
                end_line=trace.split("@")[1],
                function_name=trace.split("@")[2],
            )
            for trace in stack_trace.memory_allocate_stack_trace
            if is_valid_trace(trace)
        ]
        state.memory_free_stack_trace = [
            LocationState(
                file_name=trace.split("@")[0],
                fix_line=trace.split("@")[1],
                start_line=trace.split("@")[1],
                end_line=trace.split("@")[1],
                function_name=trace.split("@")[2],
            )
            for trace in stack_trace.memory_free_stack_trace
            if is_valid_trace(trace)
        ]

    def get_stack_trace(state: ComprehendState, thread: list[BaseMessage]):
        try:
            stack_trace: StackTraceModel = ask(
                llm, GetStackTraceCompPrompt, state, thread
            )
        except Exception as e:
            logger.error(f"Error in get_stack_trace: {e}. exiting...")
            raise e

        update_stack_trace(state, stack_trace)

    def filter_stack_trace(state: ComprehendState, thread: list[BaseMessage]):
        try:
            stack_trace: StackTraceModel = ask(
                llm, FilterStackTraceCompPrompt, state, thread
            )
        except Exception as e:
            logger.warning(
                f"Error in filter_stack_trace: {e}. Use previous stack trace."
            )
        else:
            update_stack_trace(state, stack_trace)

    def fix_wrong_filename(state: ComprehendState, thread: list[BaseMessage]):
        wrong_file_names = []
        for trace in (
            state.crash_stack_trace
            + state.memory_allocate_stack_trace
            + state.memory_free_stack_trace
        ):
            # Check the file exist
            try:
                file_location = San2PatchContextManager().find_file(trace.file_name)
                trace.file_name = file_location
            except Exception:
                wrong_file_names.append(trace.file_name)

        if wrong_file_names:
            print(
                f"[!] Wrong file names: {wrong_file_names} / Vuln. Id: {state.vuln_id}"
            )
            try:
                stack_trace: StackTraceModel = ask(
                    llm,
                    WrongStackTracePrompt,
                    {**state.model_dump(), "wrong_file_names": wrong_file_names},
                    thread,
                )
            except Exception as e:
                logger.warning(
                    f"Error in fix_wrong_filename: {e}. Use previous stack trace."
                )
            else:
                update_stack_trace(state, stack_trace)

    def get_stack_trace_codes(state: ComprehendState):
        cm = San2PatchContextManager("C", src_dir=state.package_location)

        def get_stack_trace_code(trace: LocationState):
            file_name, line_number = trace.file_name, trace.fix_line
            code_line = cm.get_code_lines(file_name, line_number, line_number)
            code_line = normalize_whitespace(code_line)

            return code_line

        for stack_trace in (
            state.crash_stack_trace
            + state.memory_allocate_stack_trace
            + state.memory_free_stack_trace
        ):
            stack_trace.code = get_stack_trace_code(stack_trace)

    @read_node_cache(
        graph_name=graph_name, cache_model=OutputState, mock=True, enabled=cached
    )
    def GetStackTrace(state: ComprehendState):
        thread = []
        # state = state.model_copy(deep=True)

        get_stack_trace(state, thread)
        filter_stack_trace(state, thread)
        fix_wrong_filename(state, thread)
        get_stack_trace_codes(state)

        return state

    def get_root_cause(
        state: ComprehendState, thread: list[BaseMessage], llm: BaseLLMPatcher
    ):
        try:
            root_cause: RootCauseModel = ask(llm_branch, RootCausePrompt, state, thread)
        except Exception as e:
            logger.warning(f"Error in get_root_cause: {e}. Leave it empty.")
            state.vuln_info.root_cause = ""
        else:
            state.vuln_info.root_cause = root_cause.vuln_root_cause

    def get_vuln_type(
        state: ComprehendState, thread: list[BaseMessage], llm: BaseLLMPatcher
    ):
        try:
            vuln_type: VulnTypeModel = ask(llm, VulnTypePrompt, state, thread)
        except Exception as e:
            logger.warning(f"Error in get_vuln_type: {e}. Leave it empty.")
            state.vuln_info.type = ""
        else:
            state.vuln_info.type = vuln_type.vuln_type

    def get_vuln_comprehension(
        state: ComprehendState, thread: list[BaseMessage], llm: BaseLLMPatcher
    ):
        try:
            vuln_comprehension: VulnDescModel = ask(llm, VulnDescPrompt, state, thread)
        except Exception as e:
            logger.warning(f"Error in get_vuln_comprehension: {e}. Leave it empty.")
            state.vuln_info.comprehension = ""
            state.vuln_info.rationale = ""
        else:
            state.vuln_info.comprehension = vuln_comprehension.vuln_description
            state.vuln_info.rationale = vuln_comprehension.rationale

    @read_node_cache(
        graph_name=graph_name, cache_model=OutputState, mock=True, enabled=cached
    )
    def BranchComprehend(state: ComprehendState):
        # We need new llm because of parallelism
        llm: BaseLLMPatcher = LLMPatcher(temperature=temperature.default)
        thread = []
        state = state.model_copy(deep=True)

        get_root_cause(state, thread, llm)
        get_vuln_type(state, thread, llm)
        get_vuln_comprehension(state, thread, llm)

        state.vuln_info_candidates = [state.vuln_info]

        return state

    def aggregate_vuln_info_candidates(
        state: ComprehendState, thread: list[BaseMessage]
    ):
        try:
            vuln_info_final: ComprehendAggregateModel = ask(
                llm, ComprehendAggregatePrompt, state, thread
            )
        except Exception as e:
            logger.error(
                f"Error in aggregate_vuln_info_candidates: {e}. Leave it empty."
            )
            state.vuln_info_final.root_cause = ""
            state.vuln_info_final.type = ""
            state.vuln_info_final.comprehension = ""
            state.vuln_info_final.rationale = ""
        else:
            state.vuln_info_final.root_cause = vuln_info_final.vuln_root_cause
            state.vuln_info_final.type = vuln_info_final.vuln_type
            state.vuln_info_final.comprehension = vuln_info_final.vuln_comprehension
            state.vuln_info_final.rationale = vuln_info_final.vuln_rationale

    @write_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    @read_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    def AggregateComprehend(state: ComprehendState):
        thread = []
        # state = state.model_copy(deep=True)

        aggregate_vuln_info_candidates(state, thread)

        return state

    # Add nodes
    comprehend_builder.add_node("comprehend_stacktrace", GetStackTrace)
    for i in range(consistency_num):
        comprehend_builder.add_node(f"comprehend_branch_{i}", BranchComprehend)
    comprehend_builder.add_node("comprehend_aggregate", AggregateComprehend)

    # Set entry and finish points
    comprehend_builder.set_entry_point("comprehend_stacktrace")
    comprehend_builder.set_finish_point("comprehend_aggregate")

    # Add edges
    for i in range(consistency_num):
        comprehend_builder.add_edge("comprehend_stacktrace", f"comprehend_branch_{i}")
        comprehend_builder.add_edge(f"comprehend_branch_{i}", "comprehend_aggregate")

    return comprehend_builder.compile()
