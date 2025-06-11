from langgraph.graph import StateGraph

from san2patch.context import San2PatchTemperatureManager
from san2patch.patching.context.code_context import get_code_block_from_file_with_lines
from san2patch.patching.graph.howtofix_graph import FixStrategyState, HowToFixFinalState
from san2patch.patching.graph.wheretofix_graph import FixLocationState, WhereToFixState
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.patch_prompts import FixStrategyModel, FixStrategyPrompt
from san2patch.utils.decorators import read_node_cache, write_node_cache
from san2patch.utils.reducers import *

TOOL_LIST = [
    get_code_block_from_file_with_lines,
]


# All
class HowToFixState(WhereToFixState, FixStrategyState, HowToFixFinalState): ...


# Input
class InputState(WhereToFixState): ...


# Output
class OutputState(HowToFixFinalState): ...


def generate_howtofix_graph(
    LLMPatcher: BaseLLMPatcher = GPT4oPatcher, cached: bool = False
):
    graph_name = "howtofix"
    howtofix_builder = StateGraph(HowToFixState)
    llm: BaseLLMPatcher = LLMPatcher(temperature=San2PatchTemperatureManager().default)

    def get_howtofix(state: HowToFixState, fix_loc_state: FixLocationState):
        strategy: FixStrategyModel = ask(
            llm, FixStrategyPrompt, {**state.model_dump(), "fix_loc": fix_loc_state}
        )

        state.fix_strategy_final = [
            FixStrategyState(
                fix_location=fix_loc_state,
                guideline=strategy.fix_guideline,
                description=strategy.fix_description,
                rationale=strategy.fix_rationale,
            )
        ]

    @read_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    @write_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    def RunHowToFix(state: HowToFixState):
        get_howtofix(state, state.fix_location_final[0])

        return state

    # Add nodes
    howtofix_builder.add_node("howtofix_run", RunHowToFix)

    # Set entry and finish points
    howtofix_builder.set_entry_point("howtofix_run")
    howtofix_builder.set_finish_point("howtofix_run")

    return howtofix_builder.compile()
