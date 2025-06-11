from langgraph.graph import StateGraph

from san2patch.patching.graph.ablation.no_comprehend.howtofix_graph import (
    generate_howtofix_graph,
)
from san2patch.patching.graph.ablation.no_comprehend.runpatch_graph import (
    RunPatchState,
    generate_runpatch_graph,
)
from san2patch.patching.graph.ablation.no_comprehend.wheretofix_graph import (
    generate_wheretofix_graph,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.utils.reducers import *


class NoComprehendPatchState(RunPatchState):
    pass


def generate_no_comprehend_patch_graph(
    LLMPatcher: BaseLLMPatcher = GPT4oPatcher,
    cached=False,
):
    graph_name = "no_comprehend_patch_graph"
    patch_builder = StateGraph(NoComprehendPatchState)

    patch_builder.add_node(
        "wheretofix",
        generate_wheretofix_graph(LLMPatcher, cached=cached).with_config(
            {"run_name": "WhereToFix"}
        ),
    )
    patch_builder.add_node(
        "howtofix",
        generate_howtofix_graph(LLMPatcher, cached=cached).with_config(
            {"run_name": "HowToFix"}
        ),
    )
    patch_builder.add_node(
        "runpatch",
        generate_runpatch_graph(LLMPatcher).with_config({"run_name": "RunPatch"}),
    )
    patch_builder.add_node("patch_end", lambda state: {"last_node": "patch_end"})

    patch_builder.set_entry_point("wheretofix")
    patch_builder.set_finish_point("patch_end")

    patch_builder.add_edge("wheretofix", "howtofix")
    patch_builder.add_edge("howtofix", "runpatch")
    patch_builder.add_edge("runpatch", "patch_end")

    return patch_builder.compile()
