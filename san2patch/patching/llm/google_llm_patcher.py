import os

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

from san2patch.consts import DEFAULT_TEMPERATURE
from san2patch.patching.prompt.base_prompts import BasePrompt

from .base_llm_patcher import BaseLLMPatcher


class GoogleAIPatcher(BaseLLMPatcher):
    name = "Google Base"
    vendor = "Google"

    def __init__(
        self,
        prompt: BasePrompt | None,
        model_name: str,
        temperature: float = DEFAULT_TEMPERATURE,
        timeout=90,
        **kwargs,
    ):
        load_dotenv(override=True)

        # get env variable from dotenv
        self.api_key = os.getenv("GOOGLE_API_KEY")

        model = ChatGoogleGenerativeAI(
            google_api_key=self.api_key,
            model=model_name,
            temperature=temperature,
            timeout=timeout,
            **kwargs,
        )

        super().__init__(model, prompt)


class Gemini15ProPatcher(GoogleAIPatcher):
    name = "Gemini 1.5 Pro"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="gemini-1.5-pro", **kwargs)


class Gemini15FlashPatcher(GoogleAIPatcher):
    name = "Gemini 1.5 Flash"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="gemini-1.5-flash", **kwargs)
