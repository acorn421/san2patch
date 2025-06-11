import glob
import os
from typing import Literal, Tuple

import tree_sitter_c as tsc
from dotenv import load_dotenv
from langsmith import traceable
from pydantic import BaseModel, Field
from tree_sitter import Language, Parser

from san2patch.utils.enum import CODE_CONTEXT_MODE
from san2patch.utils.logger import BaseLogger


class get_code_by_file_with_lines(BaseModel):
    """Retrieves the code snippet from the specified file with line numbers."""

    file_name: str = Field(
        ..., description="The name of the file to search for code snippet"
    )
    line_start: int = Field(
        ..., description="The starting line number of the code snippet"
    )
    line_end: int = Field(..., description="The ending line number of the code snippet")


class get_code_block_from_file_with_lines(BaseModel):
    """Retrieves the code block from the specified file with line numbers. Maximum line number is 100."""

    file_name: str = Field(
        ..., description="The name of the file to search for code block"
    )
    line: int = Field(..., description="The line number of the code block")


class get_func_body_from_file_with_lines(BaseModel):
    """Retrieves the code block from the specified file with line numbers. Maximum line number is 100."""

    file_name: str = Field(
        ..., description="The name of the file to search for code block"
    )
    line_start: int = Field(
        ..., description="The starting line number of the code block"
    )
    line_end: int = Field(..., description="The ending line number of the code block")


TOOL_LIST = [
    get_code_by_file_with_lines,
    get_code_block_from_file_with_lines,
    get_func_body_from_file_with_lines,
]


class CodeContextResponse(BaseModel):
    code: str
    func_def: str = ""
    func_ret: list[str] = ""


class ContextManager:
    def __init__(
        self, language: Literal["C"], src_dir, context_mode: CODE_CONTEXT_MODE = "ast"
    ):
        load_dotenv(override=True)

        self.language = language
        self.src_dir = src_dir
        self.context_mode = context_mode
        self.logger = BaseLogger(src_dir.split("/")[-1]).logger

        super().__init__()

    def find_file(self, file_name: str) -> str:
        if file_name == "":
            raise ValueError("File name cannot be empty")

        parts = file_name.split("/")
        file_location = None

        for i in range(1, len(parts) + 1):
            query = os.path.join(self.src_dir, "**", *parts[-i:])
            files = glob.glob(query, recursive=True)

            if len(files) >= 1:
                if len(files) > 1:
                    self.logger.warning(f"Multiple files found for the query: {query}")
                file_location = files[0]
            elif len(files) == 0:
                if file_location is not None:
                    break
                raise ValueError(f"File not found: {file_name}")

        file_location = file_location.replace(self.src_dir, "")

        if file_location[0] == "/":
            file_location = file_location[1:]

        return file_location

    def fix_file_name(self, file_name: str) -> str:
        return self.find_file(file_name)

    def check_code_line(self, file_name: str, line: int) -> bool:
        file_location = os.path.join(self.src_dir, file_name)

        if not os.path.exists(file_location):
            self.logger.error(f"File Not Found: {file_location}")
            return False

        with open(file_location, "r") as f:
            lines = f.readlines()

        if line > len(lines):
            return False

        return True

    def run_api_by_tool_call(self, tool_call: dict) -> dict:
        # Get the API function by tool_call["name"]
        api_name = tool_call["name"]
        api_args = tool_call["args"]

        # Get the API function by name
        func = getattr(self, api_name)

        try:
            return func(**api_args)
        except Exception as e:
            self.logger.error(f"Failed to run API by tool call: {tool_call}")
            self.logger.error(e)

            return f"Error occurred while running the API. message: {e}"

    def get_file_content(self, file_uri: str) -> str:
        # Get file content from file_uri
        file_path = file_uri.replace("file://", "").split(":")[0]
        parts = file_path.split("/")
        filename = parts[-1]
        file_locations = []
        for root, dirs, files in os.walk(self.src_dir):
            for file in files:
                if file == filename:
                    file_locations.append(os.path.join(root, file))
        if len(file_locations) == 1:
            file_path = file_locations[0]
        elif len(file_locations) > 1:
            for file_location in file_locations:
                if os.path.abspath(file_path) == os.path.abspath(file_location):
                    file_path = file_location
                    break
        else:
            return "No such file or directory"

        start_line = int(file_uri.split(":")[2])
        end_line = int(file_uri.split(":")[4])

        self.logger.debug(
            f"Getting content of {file_path} from line {start_line} to {end_line}"
        )

        with open(file_path, "r") as f:
            lines = f.readlines()

        content = "".join(lines[start_line - 1 : min(len(lines), end_line)])

        return content

    @traceable(run_type="tool")
    def get_code_lines(self, file_name: str, line_start: int, line_end: int) -> str:
        file_uri = f"file://{self.src_dir}/{file_name}:{line_start}:1:{line_end}:1"
        file_content = self.get_file_content(file_uri)

        return file_content

    def recursive_file_read(self, file_name: str) -> str | bool:
        try:
            file_location = self.find_file(file_name)
        except ValueError as e:
            self.logger.error(f"File Not Found: {e}")
            return None

        file_location = os.path.join(self.src_dir, file_location)

        if not os.path.exists(file_location):
            self.logger.error(f"File Not Found: {file_location}")
            return None

        with open(file_location, "r") as f:
            code = f.read()

        return code

    def get_function_def_and_ret(self, file_name, target_line) -> Tuple[str, list[str]]:
        code = self.recursive_file_read(file_name)

        language = tsc
        parser = Parser(Language(language.language()))
        tree = parser.parse(bytes(code, "utf8"))

        root_node = tree.root_node

        functions = []

        def traverse(node):
            if node.start_point[0] + 1 > target_line:
                return

            if node.type == "function_definition":
                pre_body_start = node.start_byte
                pre_body_end = None
                return_statements = []
                function_start_line = node.start_point[0] + 1
                function_end_line = node.end_point[0] + 1

                if function_start_line <= target_line <= function_end_line:
                    for child in node.children:
                        if child.type == "compound_statement":
                            pre_body_end = child.start_byte

                            def extract_returns(statement_node):
                                if statement_node.type == "return_statement":
                                    return_statements.append(
                                        code[
                                            statement_node.start_byte : statement_node.end_byte
                                        ].strip()
                                    )
                                for nested_child in statement_node.children:
                                    extract_returns(nested_child)

                            extract_returns(child)
                            break

                    if pre_body_end is not None:
                        pre_body_code = code[pre_body_start:pre_body_end].strip()
                        functions.append((pre_body_code, return_statements))
                        return

            for child in node.children:
                traverse(child)

        traverse(root_node)

        if len(functions) == 0:
            raise ValueError(
                f"Function not found in the file {file_name} at line {target_line}"
            )

        return functions[0]

    @traceable(run_type="tool")
    def get_func_body(self, file_name: str, line_start: int, line_end: int) -> str:
        def get_c_function_infos(node, source_code):
            function_infos = {}

            def walk_tree(node):
                if node.type == "function_definition":
                    name_node = node.child_by_field_name(
                        "declarator"
                    ).child_by_field_name("declarator")
                    if name_node:
                        function_name = source_code[
                            name_node.start_byte : name_node.end_byte
                        ].decode("utf-8")
                        function_infos[function_name] = (
                            node.start_point[0],
                            node.end_point[0],
                        )

                for child in node.children:
                    walk_tree(child)

            walk_tree(node)
            return function_infos

        language = tsc
        get_function_infos = get_c_function_infos

        code = self.recursive_file_read(file_name)

        if code is None:
            # return "The file you requested doesn't exist."
            raise ValueError("The file you requested doesn't exist.")

        parser = Parser(Language(language.language()))
        tree = parser.parse(bytes(code, "utf8"))

        # Extract function names
        function_infos = get_function_infos(tree.root_node, bytes(code, "utf8"))

        res_line = None
        for _, function_line in function_infos.items():
            # If the function line contains the line_start and line_end
            if (
                function_line[0] <= line_start <= function_line[1]
                and function_line[0] <= line_end <= function_line[1]
            ):
                res_line = function_line
                break
            # If the function line is within the line_start and line_end
            if (
                line_start <= function_line[0] <= line_end
                and line_start <= function_line[1] <= line_end
            ):
                res_line = function_line
                break

        if res_line is None:
            for _, function_line in function_infos.items():
                # If the function line contains the line_start
                if function_line[0] <= line_start <= function_line[1]:
                    res_line = function_line
                    break
                # If the function line contains the line_end
                if function_line[0] <= line_end <= function_line[1]:
                    res_line = function_line
                    break

        if res_line:
            file_uri = (
                f"file://{self.src_dir}/{file_name}:{res_line[0]}:1:{res_line[1]}:1"
            )
        else:
            self.logger.error(
                f"Function not found between lines {line_start} and {line_end} in the file."
            )
            # return "Function not found"
            raise ValueError("Function not found")

        try:
            return self.get_file_content(file_uri)
        except FileNotFoundError as e:
            self.logger.error(f"File Not Found: {e}")
            # return "The file you requested doesn't exist."
            raise ValueError("The file you requested doesn't exist.")

    @traceable(run_type="tool")
    def get_backward_code_block(
        self, file_name: str, line: int, min_line: int = 20, max_line: int = 50
    ) -> str:
        code_line = self.get_code_lines(file_name, line, line)
        original_code = self.get_code_block(
            file_name, line, min_line * 2, max_line * 2
        ).splitlines()

        return "\n".join(
            original_code[: original_code.index(code_line.replace("\n", "")) + 1]
        )

    def get_ast_node(self, file_name, line):
        code = self.recursive_file_read(file_name)

        if code is None:
            return None

        language = tsc
        parser = Parser(Language(language.language()))
        tree = parser.parse(bytes(code, "utf8"))
        root_node = tree.root_node

        def find_node_containing_line(node, line_start):
            if (
                node.start_point[0] == line_start - 1
                and line_start - 1 == node.end_point[0]
            ):
                return node
            else:
                for child in node.children:
                    result = find_node_containing_line(child, line_start)
                    if result is not None:
                        return result
            return None

        for i in range(10):
            node = find_node_containing_line(root_node, line + i)
            if node is not None:
                break

        if node is None:
            self.logger.error(
                f"Cannot find the ast node that contains line {line} in the file {file_name}"
            )

            return None

        return node

    @traceable(run_type="tool")
    def get_code_context(
        self,
        file_name: str,
        line: int,
        min_line: int = 20,
        max_line: int = 50,
        sibling: bool = True,
    ) -> CodeContextResponse:
        if self.context_mode == "line":
            avg_line = (min_line + max_line) // 2
            return CodeContextResponse(
                code=self.get_code_lines(
                    file_name, max(1, line - avg_line // 2), line + avg_line // 2
                ).strip(),
            )

        else:
            try:
                code_block = self.get_code_block(
                    file_name, line, min_line, max_line, sibling
                )
                try:
                    func_def, func_ret = self.get_function_def_and_ret(file_name, line)
                except ValueError as e:
                    self.logger.warning(f"Function not found in line {line}: {e}")
                    return CodeContextResponse(code=code_block)
            except Exception:
                avg_line = (min_line + max_line) // 2
                code_block = (
                    self.get_code_lines(
                        file_name, max(1, line - avg_line // 2), line + avg_line // 2
                    ).strip(),
                )

            return CodeContextResponse(
                code=code_block, func_def=func_def, func_ret=func_ret
            )

    def get_code_block(
        self,
        file_name: str,
        line: int,
        min_line: int = 20,
        max_line: int = 50,
        sibling: bool = True,
    ) -> str:
        # Read file_name content
        source_code = self.recursive_file_read(file_name)

        if source_code is None:
            raise ValueError("The file you requested doesn't exist.")

        node = self.get_ast_node(file_name, line)

        if node is None:
            raise ValueError("AST node not found")

        # Function to find a specific number of enclosing blocks with braces
        def find_enclosing_blocks(node, levels):
            blocks = []
            while node is not None and levels > 0:
                if (
                    node.type == "compound_statement"
                ):  # This is for blocks enclosed in {}
                    blocks.append(node.parent)
                    levels -= 1
                node = node.parent
            return blocks

        def find_direct_siblings(node):
            # Return the direct siblings(prev, next) of the node
            parent = node.parent
            prev = None
            next = None
            for i, child in enumerate(parent.children):
                if child == node:
                    if i > 0:
                        prev = parent.children[i - 1]
                    if i < len(parent.children) - 1:
                        next = parent.children[i + 1]
                    break

            return prev, next

        levels = 5  # Number of enclosing blocks to find
        # Find the specified number of enclosing blocks
        block_nodes = find_enclosing_blocks(node, levels)

        def get_code_str_by_bytes(start_byte, end_byte, source_code):
            return source_code[start_byte:end_byte]

        def get_code_block_str(node, source_code):
            # Extract the code block from the source code using bytes
            return get_code_str_by_bytes(node.start_byte, node.end_byte, source_code)

        def get_code_str_by_points(start_point, end_point, source_code):
            lines = source_code.split("\n")

            if start_point[0] == end_point[0]:
                extracted_code = lines[start_point[0]][start_point[1] : end_point[1]]
            else:
                first_line = lines[start_point[0]][start_point[1] :]
                middle_lines = lines[start_point[0] + 1 : end_point[0]]
                last_line = lines[end_point[0]][: end_point[1]]

                extracted_code = "\n".join([first_line] + middle_lines + [last_line])

            return extracted_code

        def get_code_block_str2(node, source_code):
            # Extract the code block from the source code using points
            extracted_code = get_code_str_by_points(
                node.start_point, node.end_point, source_code
            )
            if extracted_code != node.text.decode("utf-8"):
                self.logger.warning(
                    "Code block extracted using points doesn't match the node text"
                )

            return extracted_code

        # Extract and print the code blocks
        code_block_bak = None
        code_block = None
        for i, block_node in enumerate(block_nodes):
            code_block = get_code_block_str2(block_node, source_code)
            if len(code_block.split("\n")) >= min_line:
                break
            else:
                code_block_bak = code_block

        if (
            code_block
            and len(code_block.split("\n")) <= max_line
            and len(code_block.split("\n")) >= min_line
        ):
            return code_block
        elif code_block_bak and len(code_block_bak.split("\n")) >= min_line // 2:
            return code_block_bak
        elif not sibling:
            return self.get_code_lines(
                file_name=file_name,
                line_start=line - min_line // 2,
                line_end=line + min_line // 2,
            )
        else:
            # find sibling nodes and return the code block if the code block enclosed in {} doesn't make sense
            # return [parent.prev+parent+parent.next, parent.prev+parent, parent+parent.next, parent, node.prev+node+node.next, node.prev+node, node+node.next, node] in that order
            if node.parent:
                parent = node.parent
                parent_prev, parent_next = find_direct_siblings(parent)
                if parent_prev and parent_next:
                    code_str = get_code_str_by_points(
                        parent_prev.start_point, parent_next.end_point, source_code
                    )
                    if len(code_str.split("\n")) <= max_line:
                        return code_str

                if parent_prev:
                    code_str = get_code_str_by_points(
                        parent_prev.start_point, parent.end_point, source_code
                    )
                    if len(code_str.split("\n")) <= max_line:
                        return code_str

                if parent_next:
                    code_str = get_code_str_by_points(
                        parent.start_point, parent_next.end_point, source_code
                    )
                    if len(code_str.split("\n")) <= max_line:
                        return code_str

                code_str = get_code_block_str2(parent, source_code)
                if len(code_str.split("\n")) <= max_line:
                    return code_str

            node_prev, node_next = find_direct_siblings(node)
            if node_prev and node_next:
                code_str = get_code_str_by_points(
                    node_prev.start_point, node_next.end_point, source_code
                )
                if len(code_str.split("\n")) <= max_line:
                    return code_str

            if node_prev:
                code_str = get_code_str_by_points(
                    node_prev.start_point, node.end_point, source_code
                )
                if len(code_str.split("\n")) <= max_line:
                    return code_str

            if node_next:
                code_str = get_code_str_by_points(
                    node.start_point, node_next.end_point, source_code
                )
                if len(code_str.split("\n")) <= max_line:
                    return code_str

            code_str = get_code_block_str2(node, source_code)
            if len(code_str.split("\n")) <= max_line:
                return code_str

            raise ValueError("Code block not found")

    @traceable(run_type="tool")
    def get_func_body_from_code(self, code: str, function_name: str) -> str:
        self.logger.debug(
            f"Searching for function body of {function_name} in code string"
        )

        def get_c_function_body(root, source_code, func_name):
            def walk_tree(node):
                if node.type == "function_definition":
                    name_node = node.child_by_field_name(
                        "declarator"
                    ).child_by_field_name("declarator")
                    if name_node:
                        function_name = source_code[
                            name_node.start_byte : name_node.end_byte
                        ].decode("utf-8")
                        if function_name.startswith(func_name):
                            return source_code[node.start_byte : node.end_byte].decode(
                                "utf-8"
                            )

                for child in node.children:
                    ret = walk_tree(child)
                    if ret:
                        return ret

            body_content = walk_tree(root)

            if body_content is None:
                raise ValueError(f"Function {func_name} not found in the file")

            return body_content

        if self.language == "C":
            language = tsc
            get_function_body = get_c_function_body
        else:
            raise ValueError("Invalid language")

        parser = Parser(Language(language.language()))
        tree = parser.parse(bytes(code, "utf8"))

        # Extract function names
        try:
            function_body = get_function_body(
                tree.root_node, bytes(code, "utf8"), function_name
            )
        except ValueError as e:
            self.logger.error(f"Function not found: {e}")
            return "Function not found"

        return function_body
