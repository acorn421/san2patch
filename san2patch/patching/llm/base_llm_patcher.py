import getpass
import logging
import os
from typing import Generic, Literal, Type, TypeVar

import tiktoken
from dotenv import load_dotenv
from langchain.output_parsers import OutputFixingParser
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage

# flake8: noqa
from langchain_core.prompts.prompt import PromptTemplate
from langchain_experimental.utilities import PythonREPL
from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from typing_extensions import Self

from san2patch.consts import DEFAULT_TEMPERATURE
from san2patch.context import San2PatchContextManager
from san2patch.patching.prompt.base_prompts import BasePrompt
from san2patch.types import OutputT
from san2patch.utils.cmd import BaseCommander

NAIVE_JSON_FIX = """Instructions:
<Instruction>
{instructions}
</Instruction>

<Completion>
{completion}
</Completion>

Above, the Completion did not satisfy the constraints given in the Instructions.
<Error>
{error}
</Error>

<Recommendation>
- Check if you get any errors when parsing Json.
- I recommend checking if you have problems escaping special characters.
</Recommendation>

Please try again. 

Please only respond with an answer that satisfies the constraints laid out in the Instructions:"""


NAIVE_FIX_PROMPT = PromptTemplate.from_template(NAIVE_JSON_FIX)


def StructuredParser(res):
    res.__dict__["ai_message"] = AIMessage(content=str(res))

    return res


def ToolAndFixingParser(
    parser,
    fixing_model,
    logprob_keys: list | None = None,
    model_name: Literal["gpt-4o", "gpt-4"] = "gpt-4o",
):
    def output_parser(ai_message: AIMessage):
        # Debug logprobs
        def message_to_str(message: AIMessage):
            return message.content

        def find_sublist(main_list, sublist):
            # Length of the main list and sublist
            len_main, len_sub = len(main_list), len(sublist)

            # Iterate through the main list
            for i in range(len_main - len_sub + 1):
                # Check if the next len_sub elements match the sublist
                if main_list[i : i + len_sub] == sublist:
                    return i, i + len_sub  # Return the starting index of the sublist
            return -1, -1  # Indicate that the sublist was not found

        if ai_message.tool_calls:
            return {
                "tool_calls": [dict(tc) for tc in ai_message.tool_calls],
                "ai_message": ai_message,
            }
        else:
            llm = fixing_model | message_to_str
            real_parser = OutputFixingParser.from_llm(
                parser=parser, llm=llm, prompt=NAIVE_FIX_PROMPT, max_retries=3
            )
            res = real_parser.parse(ai_message.content)

            MAX_PARSE_RETRIES = 3
            for _ in range(MAX_PARSE_RETRIES):
                res = real_parser.parse(ai_message.content)
                if res is not None:
                    break

            if res is None:
                raise ValueError(
                    "Could not parse the response from the model after multiple retries."
                )

            res.__dict__["ai_message"] = ai_message
            if logprob_keys and ai_message.response_metadata["logprobs"]:
                tokens = [
                    x["token"]
                    for x in ai_message.response_metadata["logprobs"]["content"]
                ]

                if model_name == "gpt-4o":
                    enc = tiktoken.get_encoding("o200k_base")
                else:
                    enc = tiktoken.get_encoding("cl100k_base")

                # To get the tokeniser corresponding to a specific model in the OpenAI API:

                final_logprob = {}
                for logprob_key in logprob_keys:
                    possible_key_strs = [
                        f'"{logprob_key}":',
                        f' "{logprob_key}":',
                        f'"{logprob_key}" :',
                        f' "{logprob_key}" :',
                    ]
                    posibble_key_encodes = [
                        enc.encode(key_str) for key_str in possible_key_strs
                    ]
                    possible_key_bytes = []
                    for token_list in posibble_key_encodes:
                        possible_key_bytes.append(
                            [
                                enc.decode_single_token_bytes(token).decode()
                                for token in token_list
                            ]
                        )

                    for possible_key in possible_key_bytes:
                        key_start, key_end = find_sublist(tokens, possible_key)
                        # Found
                        if key_end != -1:
                            body_start, body_end = -1, -1

                            for idx, token in enumerate(tokens[key_end:]):
                                # Start body
                                if '"' in token:
                                    if body_start == -1:
                                        body_start = key_end + idx + 1
                                        continue
                                    else:
                                        body_end = key_end + idx
                                        break

                    if body_start == -1 or body_end == -1:
                        raise ValueError(
                            f"Could not find the key {logprob_key} in the logprobs"
                        )

                    logprob_probs = ai_message.response_metadata["logprobs"]["content"][
                        body_start:body_end
                    ]
                    final_logprob[logprob_key] = logprob_probs
                res["logprobs"] = final_logprob

            return res

    return output_parser


class BaseLLMPatcher(BaseCommander, Generic[OutputT]):
    name = "base"
    vendor = "base"

    def __init__(
        self,
        model: BaseChatModel,
        prompt: BasePrompt[OutputT] | None = None,
        log_level: int = logging.WARNING,
        log_file: str | None = None,
        temperature: int = DEFAULT_TEMPERATURE,
        langsmith: bool = True,
        structured: bool = True,
    ):
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.logger.setLevel(log_level)

        # If langsmith api key is not set, set env variable using dotenv
        if langsmith and not os.getenv("LANGSMITH_API_KEY"):
            langsmith = False

        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setLevel(log_level)

            self.logger.addHandler(fh)

        self.model = model
        self.structured = structured
        self.temperature = temperature

        if prompt is not None:
            self.set_prompt(prompt)

    def set_prompt(self, prompt: BasePrompt[OutputT]) -> Self:
        self.prompt = prompt
        self.structured_model = self.model.with_structured_output(prompt.output_pyantic)

        if not self.structured:
            self.fixing_model = ChatOpenAI(
                openai_api_key=os.getenv("OPENAI_API_KEY"), model="gpt-4o-mini"
            )

            if self.prompt.logprob_keys:
                if self.vendor == "OpenAI":
                    self.final_parser = ToolAndFixingParser(
                        self.prompt.parser, self.fixing_model, self.prompt.logprob_keys
                    )
                else:
                    self.final_parser = ToolAndFixingParser(
                        self.prompt.parser, self.fixing_model
                    )
                    self.logger.warning(
                        f"Vendor {self.vendor} does not support logprobs. Ignoring logprob_keys"
                    )
            else:
                self.final_parser = ToolAndFixingParser(
                    self.prompt.parser, self.fixing_model
                )

            self.chain = (
                self.prompt.template | self.model | self.final_parser
            ).with_config({"run_name": self.prompt.__class__.__name__})
        else:
            self.structured_model = self.model.with_structured_output(
                prompt.output_pyantic
            )
            self.final_parser = StructuredParser
            self.chain = (
                self.prompt.template | self.structured_model | self.final_parser
            ).with_config({"run_name": self.prompt.__class__.__name__})

        return self

    def bind_tools(
        self, tools: list, language: Literal["C"], context_settings: dict = {}
    ) -> None:
        if self.structured:
            self.logger.warning("Cannot bind tools to structured model. Ignoring.")
            return

        try:
            self.model = self.model.bind_tools(tools)
            self.chain = (
                self.prompt.template | self.model | self.final_parser
            ).with_config({"run_name": self.prompt.__class__.__name__})
            self.cm = San2PatchContextManager(language, **context_settings)
            self.python_repl = PythonREPL()
        except Exception as e:
            self.logger.warning(f"Cannot bind tools to {self.name}: {e}")
            self.logger.warning(f"Invoke without tools")

    def invoke(self, inputs: dict | BaseModel) -> OutputT:
        if isinstance(inputs, BaseModel):
            inputs = inputs.__dict__

        # def dumb_wrapper(inputs, template):
        #     return template.

        if self.prompt.is_jinja:
            self.prompt.update_template_with_input(inputs)
            if not self.structured:
                self.chain = (
                    self.prompt.template | self.model | self.final_parser
                ).with_config({"run_name": self.prompt.__class__.__name__})
            else:
                self.chain = (
                    self.prompt.template | self.structured_model | self.final_parser
                ).with_config({"run_name": self.prompt.__class__.__name__})

        MAX_INVOKE_RETRIES = 2
        for i in range(MAX_INVOKE_RETRIES):
            try:
                res = self.chain.invoke(inputs)
                if "tool_calls" in res:
                    return res
                else:
                    if isinstance(res, BaseModel):
                        try:
                            self.prompt.output_pyantic.validate(res)
                        except Exception as e:
                            self.logger.warning(
                                f"Output does not match the expected pydantic model. Retrying. Retry count: {i}"
                            )
                            continue
                        return res
                    elif isinstance(res, dict):
                        if all(
                            (key in res.keys())
                            for key in self.prompt.output_pyantic.__fields__.keys()
                        ):
                            return res
                    else:
                        self.logger.warning(
                            f"Output does not match the expected pydantic model. Retrying. Retry count: {i}"
                        )
                        continue
            except Exception as e:
                self.logger.warning(f"Error when invoking chain: {e}. Retry count: {i}")
                if i == MAX_INVOKE_RETRIES - 1:
                    raise e
                continue

        self.logger.fatal(
            f"Could not invoke the chain after {MAX_INVOKE_RETRIES} retries."
        )

        raise ValueError("Could not invoke the chain after multiple retries.")

    def invoke_with_tools(self, inputs: dict | BaseModel):
        if isinstance(inputs, BaseModel):
            inputs = inputs.__dict__

        while True:
            res = self.invoke(inputs)

            if res != False and "tool_calls" in res:
                self.prompt.template.messages.append(res["ai_message"])

                for tool_call in res["tool_calls"]:
                    if tool_call["name"] == "python_repl":
                        self.python_repl.run(**tool_call["args"])

                    tool_res = self.cm.run_api_by_tool_call(tool_call)
                    if tool_call["name"] == "get_func_body_by_name":
                        MAX_LEN = 500
                        total_length = 0
                        for tool_r in tool_res:
                            total_length += len(tool_r.split("\n"))

                        if total_length > MAX_LEN:
                            tool_res = f"get_func_body_by_name({tool_call['args']}) returns too long. So I can't provide the entire code. If you need {tool_call['args']}'s code content, use a code block using the get_func_body_from_file_with_lines function call."

                    self.prompt.template.messages.append(
                        ToolMessage(str(tool_res), tool_call_id=tool_call["id"])
                    )
            else:
                return res


def ask(
    llm: BaseLLMPatcher,
    prompt_cls: Type[BasePrompt[OutputT]],
    state: BaseModel,
    thread: list[BaseMessage] | None = None,
    append: bool = True,
) -> OutputT:
    prompt = prompt_cls(messages=thread)
    llm_res = llm.set_prompt(prompt).invoke(state)
    if append and thread is not None:
        thread[:] = prompt.template.messages + [llm_res.ai_message]
    return llm_res
