import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from san2patch.consts import DEFAULT_TEMPERATURE
from san2patch.patching.prompt.base_prompts import BasePrompt

from .base_llm_patcher import BaseLLMPatcher


class OpenAIPatcher(BaseLLMPatcher):
    name = "OpenAI Base"
    vendor = "OpenAI"

    def __init__(
        self,
        prompt: BasePrompt | None,
        model_name: str,
        temperature: float = DEFAULT_TEMPERATURE,
        timeout=90,
        structured: bool = True,
        **kwargs,
    ):
        load_dotenv(override=True)

        # get env variable from dotenv
        self.api_key = os.getenv("OPENAI_API_KEY")

        if prompt is not None and prompt.logprob_keys:
            model = ChatOpenAI(
                openai_api_key=self.api_key,
                model=model_name,
                temperature=temperature,
                timeout=timeout,
                **kwargs,
            ).bind(logprobs=True)
        else:
            model = ChatOpenAI(
                openai_api_key=self.api_key,
                model=model_name,
                temperature=temperature,
                timeout=timeout,
                **kwargs,
            )

        super().__init__(model, prompt, structured=structured)


class GPT4ominiPatcher(OpenAIPatcher):
    name = "GPT-4o-mini"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="gpt-4o-mini", **kwargs)


class GPT35Patcher(OpenAIPatcher):
    name = "GPT-3.5"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(
            prompt, model_name="gpt-3.5-turbo-0125", structured=False, **kwargs
        )


class GPT4Patcher(OpenAIPatcher):
    name = "GPT-4"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="gpt-4-turbo-2024-04-09", **kwargs)


class GPT4oPatcher(OpenAIPatcher):
    name = "GPT-4o"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="gpt-4o-2024-08-06", **kwargs)
