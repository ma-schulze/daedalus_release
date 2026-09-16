import os
from anthropic import Anthropic

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise ValueError("ANTHROPIC_API_KEY is not set")

client = Anthropic()
DEFAULT_MODEL = "claude-opus-4-7"


def call_llm(
    user_prompt: str,
    system_prompt: str | None = None,
    model: str | None = None,
) -> str:
    """
    Call the Anthropic API with the given prompts.
    Returns the generated text (first content block text).
    """
    kwargs: dict = {
        "model": model or DEFAULT_MODEL,
        "max_tokens": 8192,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    if system_prompt:
        kwargs["system"] = system_prompt

    print(kwargs)
    response = client.messages.create(**kwargs)
    if not response.content:
        raise RuntimeError("LLM returned empty response")
    text = response.content[0].text
    if not text:
        raise RuntimeError("LLM returned empty response")
    return text
