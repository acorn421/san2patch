from collections import defaultdict
from functools import partial
from typing import Annotated

import numpy as np
from langgraph.graph import StateGraph
from pydantic import BaseModel

from san2patch.consts import SCORE_ALPHA
from san2patch.context import San2PatchLogger, San2PatchTemperatureManager
from san2patch.patching.context.code_context import get_code_block_from_file_with_lines
from san2patch.patching.graph.ablation.no_comprehend.wheretofix_graph import (
    FixLocationState,
    WhereToFixState,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.eval_prompts import EvalModel, HowToFixEvalPrompt
from san2patch.patching.prompt.patch_prompts import FixStrategyBranchPrompt
from san2patch.utils.decorators import read_node_cache, write_node_cache
from san2patch.utils.reducers import *

TOOL_LIST = [
    get_code_block_from_file_with_lines,
]


# How-To-Fix core state
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


class HowToFixBranchState(BaseModel):
    fix_strategy_candidates: Annotated[list[FixStrategyState], reduce_list] = []


class HowToFixFinalState(BaseModel):
    fix_strategy_final: Annotated[list[FixStrategyState], fixed_value] = []


# All
class HowToFixState(
    WhereToFixState, FixStrategyState, HowToFixBranchState, HowToFixFinalState
): ...


# Input
class InputState(WhereToFixState): ...


# Output
class OutputState(HowToFixFinalState): ...


def generate_howtofix_graph(
    LLMPatcher: BaseLLMPatcher = GPT4oPatcher,
    branch_num: int = 3,
    select_num: int = 1,
    cached: bool = False,
):
    graph_name = "howtofix"
    howtofix_builder = StateGraph(HowToFixState)
    temperature = San2PatchTemperatureManager()
    llm: BaseLLMPatcher = LLMPatcher(temperature=temperature.default)
    llm_branch: BaseLLMPatcher = LLMPatcher(temperature=temperature.branch)
    logger = San2PatchLogger().logger

    def get_howtofix(state: HowToFixState, fix_loc_state: FixLocationState):
        prompt_cls = partial(FixStrategyBranchPrompt, branch_num=branch_num)

        try:
            strategy = ask(
                llm_branch, prompt_cls, {**state.model_dump(), "fix_loc": fix_loc_state}
            )
        except Exception as e:
            logger.warning(f"Failed to get how-to-fix. Skipping. {e}")
        else:
            state.fix_strategy_candidates.extend(
                [
                    FixStrategyState(
                        fix_location=fix_loc_state,
                        guideline=strategy.__getattribute__(f"fix_guideline_{i}"),
                        description=strategy.__getattribute__(f"fix_description_{i}"),
                        rationale=strategy.__getattribute__(f"fix_rationale_{i}"),
                    )
                    for i in range(1, branch_num + 1)
                ]
            )

    @read_node_cache(
        graph_name=graph_name, cache_model=OutputState, mock=True, enabled=cached
    )
    def BranchHowToFix(state: HowToFixState):
        for fix_loc_state in state.fix_location_final:
            get_howtofix(state, fix_loc_state)

        return state

    def eval_howtofix(state: HowToFixState, strategy_state: FixStrategyState):
        try:
            eval_res: EvalModel = ask(
                llm,
                HowToFixEvalPrompt,
                {**state.model_dump(), "strategy": strategy_state},
            )
        except Exception as e:
            logger.warning(f"Failed to evaluate how-to-fix. Set minimum score. {e}")
            strategy_state.score = 0.1
            strategy_state.confidence = 0.1
            strategy_state.reliability_score = strategy_state.score * (
                1 + SCORE_ALPHA * strategy_state.confidence
            )
            strategy_state.eval_rationale = ""
        else:
            strategy_state.score = eval_res.numeric_score
            strategy_state.confidence = eval_res.confidence
            strategy_state.reliability_score = strategy_state.score * (
                1 + SCORE_ALPHA * strategy_state.confidence
            )
            strategy_state.eval_rationale = eval_res.rationale

        return state

    def select_howtofix(state: HowToFixState):
        # Evaluate each strategy
        for strategy_state in state.fix_strategy_candidates:
            eval_howtofix(state, strategy_state)

        # Group by parent node
        grouped_fix_strategies: dict[int, list[FixStrategyState]] = defaultdict(list)
        for strategy in state.fix_strategy_candidates:
            grouped_fix_strategies[hash(strategy.fix_location)].append(strategy)

        # Select the best strategy for each parent node
        for _, strategies in grouped_fix_strategies.items():
            scores = [strategy.reliability_score for strategy in strategies]
            select_size = min(select_num, len(strategies))
            ids = list(range(len(strategies)))
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
            state.fix_strategy_final.extend([strategies[i] for i in select_ids])

        # Sort by reliability score for prioritization in patch generation
        state.fix_strategy_final.sort(key=lambda x: x.reliability_score, reverse=True)

    @read_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    @write_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    def SelectHowToFix(state: HowToFixState):
        select_howtofix(state)
        return state

    # Add nodes
    howtofix_builder.add_node("howtofix_branch", BranchHowToFix)
    howtofix_builder.add_node("howtofix_select", SelectHowToFix)

    # Set entry and finish points
    howtofix_builder.set_entry_point("howtofix_branch")
    howtofix_builder.set_finish_point("howtofix_select")

    # Add edges
    howtofix_builder.add_edge("howtofix_branch", "howtofix_select")

    return howtofix_builder.compile()
