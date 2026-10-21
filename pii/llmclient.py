"""LLM span extraction — the recall pass of the sterilizer.

The model is a sensor, never an actor: it proposes verbatim substrings
plus a type from the closed vocabulary, grammar-constrained via
llama.cpp's json_schema response_format (off-schema output is
impossible). It never rewrites text — pipeline.py grounds every proposed
span against the input (verbatim occurrence or it is dropped and
counted) and performs all replacement itself, so the model cannot rewrite
the text whatever it outputs.

Talks OpenAI-style chat completions to a llama.cpp-compatible server at
LLM_URL, with thinking disabled per request via chat_template_kwargs.
Stdlib urllib only.
"""

import json
import urllib.request
from typing import List, Tuple

from .detect import PII_TYPES

Findings = List[Tuple[str, str]]

_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "type": {"type": "string", "enum": PII_TYPES},
                },
                "required": ["text", "type"],
            },
        }
    },
    "required": ["findings"],
}

# The exact vocabulary MUST appear in the prompts. The grammar constrains
# type to this enum, but grammar is a backstop, not steering: a model that
# free-texts "School" gets prefix-coerced to "SSN" (seen with a real model).
# test_pii guards prompt/enum drift.
_TYPE_LIST = ", ".join(PII_TYPES)

EXTRACT_SYSTEM = f"""You are a PII detector for a privacy gateway. List every substring of the user's text that could identify a person, household, account, or device.

Label each finding with exactly one of these types (use the label verbatim):
{_TYPE_LIST}

Find: personal names; email addresses; phone numbers; street or postal addresses; government/tax/license/passport ID numbers; credit card and bank account numbers; dates of birth; usernames and social handles; passwords, API keys, and other secrets; medical facts tied to a person; employers, schools, or organizations that identify someone; specific places that identify someone (their home, school, workplace); IP addresses; MAC addresses and device serial numbers.

Rules:
- Copy each span VERBATIM, character for character, exactly as it appears in the text. Never paraphrase, correct, or reformat.
- Report the minimal identifying span, without surrounding punctuation or filler words.
- If the same value appears multiple times, report it once.
- Do not report placeholder tokens that look like [PII_TYPE_N] — those are already sterilized.
- Generic words, product names, and public facts are not PII. When a span does not identify anyone, leave it out.
- If there is no PII, return an empty findings list."""

VERIFY_SYSTEM = f"""You are auditing a sterilized document for residual PII. Placeholder tokens like [PII_EMAIL_1] are already sterilized — ignore them. Report ONLY remaining substrings that could still identify a person, household, account, or device, copied verbatim, each labeled with exactly one of these types (use the label verbatim): {_TYPE_LIST}. Be aggressive: a partial address, a first name, a nickname, an unusual job title can all identify someone. If nothing identifying remains, return an empty findings list."""


class RecallError(RuntimeError):
    """The recall pass could not run. Every backend raises this (or a
    subclass); the service fails closed on it. Defined here so the older
    LlmError keeps its name while sharing the contract."""


class LlmError(RecallError):
    pass


def _chat(llm_url: str, system: str, text: str, timeout: float) -> Findings:
    body = json.dumps({
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": text},
        ],
        "temperature": 0,
        "chat_template_kwargs": {"enable_thinking": False},
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "pii_findings", "schema": _SCHEMA},
        },
    }).encode()
    req = urllib.request.Request(
        llm_url.rstrip("/") + "/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.load(resp)
    except OSError as e:
        raise LlmError(f"llm unreachable: {e}") from e
    try:
        content = payload["choices"][0]["message"]["content"]
        findings = json.loads(content)["findings"]
        return [(f["text"], f["type"]) for f in findings]
    except (KeyError, IndexError, TypeError, ValueError) as e:
        raise LlmError(f"malformed llm response: {e}") from e


def extract(text: str, llm_url: str, timeout: float = 300.0) -> Findings:
    return _chat(llm_url, EXTRACT_SYSTEM, text, timeout)


def verify(text: str, llm_url: str, timeout: float = 300.0) -> Findings:
    return _chat(llm_url, VERIFY_SYSTEM, text, timeout)
