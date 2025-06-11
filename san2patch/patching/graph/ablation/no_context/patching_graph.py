from langgraph.graph import StateGraph

from san2patch.patching.graph.comprehend_graph import generate_comprehend_graph
from san2patch.patching.graph.howtofix_graph import generate_howtofix_graph
from san2patch.patching.graph.runpatch_graph import (
    RunPatchState,
    generate_runpatch_graph,
)
from san2patch.patching.graph.wheretofix_graph import generate_wheretofix_graph
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.utils.reducers import *


class NoContextPatchState(RunPatchState):
    pass


def generate_no_context_patch_graph(
    LLMPatcher: BaseLLMPatcher = GPT4oPatcher,
    cached=False,
):
    graph_name = "no_context_patch_graph"
    patch_builder = StateGraph(NoContextPatchState)

    patch_builder.add_node(
        "comprehend",
        generate_comprehend_graph(LLMPatcher, cached=cached).with_config(
            {"run_name": "Comprehend"}
        ),
    )
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

    patch_builder.set_entry_point("comprehend")
    patch_builder.set_finish_point("patch_end")

    patch_builder.add_edge("comprehend", "wheretofix")
    patch_builder.add_edge("wheretofix", "howtofix")
    patch_builder.add_edge("howtofix", "runpatch")
    patch_builder.add_edge("runpatch", "patch_end")

    return patch_builder.compile()
