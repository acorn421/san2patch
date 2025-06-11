import json
import os
from typing import Type

from pydantic import BaseModel

from san2patch.context import San2PatchLogger


def read_node_cache(
    graph_name: str,
    cache_model: Type[BaseModel],
    mock: bool = False,
    enabled: bool = False,
):
    def decorator(func):
        if not enabled:
            return func

        def wrapper(state: BaseModel | dict):
            cache_name = f"{graph_name}_output.json"
            if os.path.exists(os.path.join(state.diff_stage_dir, "..", cache_name)):
                San2PatchLogger().logger.debug(
                    f"{cache_name} exists. Loading saved state."
                )

                if mock:
                    return {"last_node": "cached"}

                with open(
                    os.path.join(state.diff_stage_dir, "..", cache_name),
                    "r",
                ) as f:
                    new_state_dict = json.load(f)

                    new_state = cache_model(**new_state_dict)

                    return new_state

            return func(state)

        return wrapper

    return decorator


def write_node_cache(
    graph_name: str, cache_model: Type[BaseModel], enabled: bool = False
):
    def decorator(func):
        if not enabled:
            return func

        def wrapper(state: BaseModel | dict):
            new_state = func(state)

            cache_state = cache_model(**new_state.dict())
            cache_name = f"{graph_name}_output.json"

            with open(os.path.join(state.diff_stage_dir, "..", cache_name), "w") as f:
                json.dump(cache_state.model_dump(), f)

            San2PatchLogger().logger.debug(f"Saved state to {cache_name}")

            return new_state

        return wrapper

    return decorator
