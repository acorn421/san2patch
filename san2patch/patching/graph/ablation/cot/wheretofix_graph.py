from langgraph.graph import StateGraph

from san2patch.context import (
    San2PatchContextManager,
    San2PatchLogger,
    San2PatchTemperatureManager,
)
from san2patch.patching.context.code_context import (
    get_code_block_from_file_with_lines,
    get_code_by_file_with_lines,
)
from san2patch.patching.graph.comprehend_graph import (
    ComprehendState,
    LocationState,
)

# from san2patch.patching.graph.howtofix_graph import HowToFixState
from san2patch.patching.graph.wheretofix_graph import (
    FixLocationState,
    LocationCandidatesState,
    WhereToFixFinalState,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.patch_prompts import (
    FaultLocalModel,
    SelectLocationPrompt,
)
from san2patch.utils.decorators import read_node_cache, write_node_cache
from san2patch.utils.jinja import trace_to_str
from san2patch.utils.reducers import *

TOOL_LIST = [
    get_code_by_file_with_lines,
    get_code_block_from_file_with_lines,
]


# All
class WhereToFixState(
    ComprehendState, LocationCandidatesState, WhereToFixFinalState
): ...


# Input
class InputState(ComprehendState): ...


# Output
class OutputState(WhereToFixFinalState): ...


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


def generate_wheretofix_graph(
    LLMPatcher: BaseLLMPatcher = GPT4oPatcher, cached: bool = False
):
    graph_name = "wheretofix"
    wheretofix_builder = StateGraph(WhereToFixState)
    llm: BaseLLMPatcher = LLMPatcher(temperature=San2PatchTemperatureManager().default)
    logger = San2PatchLogger().logger

    def get_fix_location_candidates(state: WhereToFixState):
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

        for retry_cnt in range(3):
            fault_local: FaultLocalModel = ask(llm, SelectLocationPrompt, state)

            try:
                fault_local.validate_self(check_code=True)
            except Exception as e:
                logger.warning(f"Error in fault_local: {e}. trying to fix the filename")
                try:
                    fault_local.fix_filename()
                except Exception as e:
                    logger.warning(
                        f"Error in fault_local: {e}. Re-ask the question {retry_cnt + 1}"
                    )
                    continue
                else:
                    break
            else:
                break

        # Parse the results
        selected_stack_trace = fault_local.selected_stack_trace
        fix_loc = fault_local.fix_locations
        rationale = fault_local.fix_location_rationale

        fix_location = FixLocationState()

        for loc in fix_loc:
            code = get_code_line(
                loc.fix_file_name, loc.fix_line, loc.fix_line, state.package_location
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

        state.fix_location_final = [fix_location]

        # Restore the stack traces
        state.crash_stack_trace = crash_stack_trace_bak
        state.memory_allocate_stack_trace = memory_allocate_stack_trace_bak
        state.memory_free_stack_trace = memory_free_stack_trace_bak

    @read_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    @write_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    def RunWhereToFix(state: WhereToFixState):
        get_fix_location_candidates(state)

        return state

    wheretofix_builder.add_node("wheretofix_run", RunWhereToFix)

    wheretofix_builder.set_entry_point("wheretofix_run")
    wheretofix_builder.set_finish_point("wheretofix_run")

    return wheretofix_builder.compile()
