from pydantic import BaseModel, Field

from san2patch.patching.prompt.base_prompts import BasePrompt


# Models
class EvalModel(BaseModel):
    numeric_score: int = Field(
        description="Provide a numeric evaluation of the LLM's answer. Select a number between 1 (worst) and 10 (best)."
    )
    confidence: int = Field(
        description="Indicate your confidence in the given numeric score. Provide a number between 1 (no confidence) and 10 (absolute confidence)."
    )
    rationale: str = Field(
        description="Explain the reasoning behind the numeric score you provided."
    )


# Prompts
class HowToFixEvalPrompt(BasePrompt):
    def __init__(self, **kwargs):
        super().__init__(EvalModel, "howtofix/eval.jinja2", **kwargs)


class WhereToFixEvalPrompt(BasePrompt):
    def __init__(self, **kwargs):
        super().__init__(EvalModel, "wheretofix/eval.jinja2", **kwargs)
