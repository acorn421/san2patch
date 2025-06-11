import warnings
from collections.abc import Iterable
from xml.dom.minidom import parseString

from pydantic import BaseModel


def fixed_value(left, right):
    if type(left) is type(right):
        return right if right else left
    elif (
        isinstance(right, Iterable)
        and not isinstance(right, BaseModel)
        and len(right) > 0
        and type(left) is type(right[0])
    ):
        s = set(right)

        if left:
            s.add(left)

        return next(iter(s))
    else:
        warnings.warn(
            f"Something is wrong with the types of left and right.: {type(left)=}, {type(right)=}"
        )
        return right if right else left


def fixed_dict(left, right):
    if not right:
        if not left:
            return {}
        return left

    for keys in right.keys():
        if keys in left.keys():
            left[keys] = fixed_value(left[keys], right[keys])
        else:
            left[keys] = right[keys]

    return left


def reduce_list(left: list | None, right: list | None) -> list:
    if (len(left) != 1 and len(right) != 1) and left == right:
        return right
    if not left:
        left = []
    if not right:
        right = []
    return left + right


def unlist_state(state: dict):
    new_state = {}
    for k, v in state.items():
        if isinstance(v, list):
            for i, item in enumerate(v):
                new_state[f"{k}[{i}]"] = item
        new_state[k] = v
    return new_state


def pretty_print_xml(xml_str: str, indent: str = "  ") -> str:
    """Pretty print XML and remove the XML declaration."""
    dom = parseString(xml_str)
    pretty_xml = dom.toprettyxml(indent=indent)
    return "\n".join(pretty_xml.split("\n")[1:])
