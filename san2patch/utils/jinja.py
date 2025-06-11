from xml.dom.minidom import parseString

from dicttoxml import dicttoxml
from jinja2 import Environment
from pydantic import BaseModel

INDENT = "    "


def trace_to_str(trace):
    return f"{trace.file_name}@{trace.start_line}@{trace.function_name}"


def loc_to_str(loc):
    return f"{loc.file_name}:{loc.start_line}:{loc.end_line}"


def convert_to_xml(value, key: str):
    """Convert a dictionary or list to XML string."""
    if value is None or value == "":
        return ""

    if isinstance(value, BaseModel):
        value = value.model_dump()

    if isinstance(value, dict):
        # check if the dict is empty like dummy vuln info state
        for _, v in value.items():
            if v != "" or v is not None:
                break
        else:
            return ""

    xml_bytes = dicttoxml(value, custom_root=key, attr_type=False)

    # Pretty print the XML
    dom = parseString(xml_bytes)
    pretty = dom.toprettyxml(indent=INDENT)
    return "\n".join(pretty.split("\n")[1:])


def adjust_indent(xml_string: str, base_indent):
    """
    Adjust the indent of XML content to match the Jinja2 template's current indentation.
    """
    lines = xml_string.splitlines()
    adjusted_lines = [
        (base_indent * INDENT + line) if line.strip() else line for line in lines
    ]
    return "\n".join(adjusted_lines)


jinja_env = Environment(autoescape=False)

jinja_env.filters["to_xml"] = convert_to_xml
jinja_env.filters["adjust_indent"] = adjust_indent
jinja_env.filters["trace_to_str"] = trace_to_str
jinja_env.filters["loc_to_str"] = loc_to_str
