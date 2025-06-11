import os

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic

from san2patch.consts import DEFAULT_TEMPERATURE
from san2patch.patching.prompt.base_prompts import BasePrompt

from .base_llm_patcher import BaseLLMPatcher


class AnthropicPatcher(BaseLLMPatcher):
    name = "Anthropic Base"
    vendor = "Anthropic"

    def __init__(
        self,
        prompt: BasePrompt,
        model_name: str,
        temperature: float = DEFAULT_TEMPERATURE,
        timeout=90,
        **kwargs,
    ):
        load_dotenv(override=True)

        # get env variable from dotenv
        self.api_key = os.getenv("ANTHROPIC_API_KEY")

        model = ChatAnthropic(
            model_name=model_name,
            anthropic_api_key=self.api_key,
            max_tokens=8192,
            temperature=temperature,
            timeout=timeout,
            **kwargs,
        )

        super().__init__(model, prompt)


class Claude35SonnetPatcher(AnthropicPatcher):
    name = "Claude 3.5 Sonnet"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="claude-3-5-sonnet-20240620", **kwargs)


class Claude3OpusPatcher(AnthropicPatcher):
    name = "Claude 3 Opus"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="claude-3-opus-20240229", **kwargs)


class Claude3SonnetPatcher(AnthropicPatcher):
    name = "Claude 3 Sonnet"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="claude-3-sonnet-20240229", **kwargs)


class Claude3HaikuPatcher(AnthropicPatcher):
    name = "Claude 3 Haiku"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="claude-3-haiku-20240307", **kwargs)
