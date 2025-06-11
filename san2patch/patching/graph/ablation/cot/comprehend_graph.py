from typing import Type

from langchain_core.messages import BaseMessage
from langgraph.graph import StateGraph

from san2patch.context import (
    San2PatchContextManager,
    San2PatchLogger,
    San2PatchTemperatureManager,
)
from san2patch.patching.context.code_context import (
    get_code_block_from_file_with_lines,
)
from san2patch.patching.graph.comprehend_graph import (
    CopmrehendFinalState,
    LocationState,
    StackTraceState,
    VDState,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.patch_prompts import (
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


# All
class CoTComprehendState(VDState, StackTraceState, CopmrehendFinalState): ...


# Input
class InputState(VDState): ...


# Output
class OutputState(CopmrehendFinalState, StackTraceState): ...


TOOL_LIST = [
    get_code_block_from_file_with_lines,
]


def generate_comprehend_graph(
    LLMPatcher: Type[BaseLLMPatcher[OutputT]] = GPT4oPatcher, cached: bool = False
):
    graph_name = "comprehend"
    comprehend_builder = StateGraph(CoTComprehendState)
    llm: BaseLLMPatcher = LLMPatcher(temperature=San2PatchTemperatureManager().default)
    logger = San2PatchLogger().logger

    def update_stack_trace(state: CoTComprehendState, stack_trace: StackTraceModel):
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

    def get_stack_trace(state: CoTComprehendState, thread: list[BaseMessage]):
        stack_trace: StackTraceModel = ask(llm, GetStackTraceCompPrompt, state, thread)

        update_stack_trace(state, stack_trace)

    def filter_stack_trace(state: CoTComprehendState, thread: list[BaseMessage]):
        stack_trace: StackTraceModel = ask(
            llm, FilterStackTraceCompPrompt, state, thread
        )

        update_stack_trace(state, stack_trace)

    def fix_wrong_filename(state: CoTComprehendState, thread: list[BaseMessage]):
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
            logger.warning(
                f"[!] Wrong file names: {wrong_file_names} / Vuln. Id: {state.vuln_id}"
            )
            stack_trace: StackTraceModel = ask(
                llm,
                WrongStackTracePrompt,
                {**state.model_dump(), "wrong_file_names": wrong_file_names},
                thread,
            )

            update_stack_trace(state, stack_trace)

    def get_stack_trace_codes(state: CoTComprehendState):
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
    def GetStackTrace(state: CoTComprehendState):
        thread = []
        # state = state.model_copy(deep=True)

        get_stack_trace(state, thread)
        filter_stack_trace(state, thread)
        fix_wrong_filename(state, thread)
        get_stack_trace_codes(state)

        return state

    def get_root_cause(state: CoTComprehendState, thread: list[BaseMessage]):
        root_cause: RootCauseModel = ask(llm, RootCausePrompt, state, thread)

        state.vuln_info_final.root_cause = root_cause.vuln_root_cause

    def get_vuln_type(state: CoTComprehendState, thread: list[BaseMessage]):
        vuln_type: VulnTypeModel = ask(llm, VulnTypePrompt, state, thread)

        state.vuln_info_final.type = vuln_type.vuln_type

    def get_vuln_comprehension(state: CoTComprehendState, thread: list[BaseMessage]):
        vuln_comprehension: VulnDescModel = ask(
            llm,
            VulnDescPrompt,
            {**state.model_dump(), "vuln_info": state.vuln_info_final},
            thread,
        )

        state.vuln_info_final.comprehension = vuln_comprehension.vuln_description
        state.vuln_info_final.rationale = vuln_comprehension.rationale

    @read_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    @write_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    def RunComprehend(state: CoTComprehendState):
        thread = []
        state = state.model_copy(deep=True)

        get_root_cause(state, thread)
        get_vuln_type(state, thread)
        get_vuln_comprehension(state, thread)

        return state

    # Add nodes
    comprehend_builder.add_node("comprehend_stacktrace", GetStackTrace)
    comprehend_builder.add_node("comprehend_run", RunComprehend)

    # Set entry and finish points
    comprehend_builder.set_entry_point("comprehend_stacktrace")
    comprehend_builder.set_finish_point("comprehend_run")

    # Add edges
    comprehend_builder.add_edge("comprehend_stacktrace", "comprehend_run")

    return comprehend_builder.compile()
