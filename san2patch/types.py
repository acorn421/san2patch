from typing import TypeVar

from pydantic import BaseModel

OutputT = TypeVar("PromptRet", bound=BaseModel)
