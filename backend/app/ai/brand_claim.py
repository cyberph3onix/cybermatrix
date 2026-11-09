"""LLM extraction of the brand a page presents itself as, plus whether it asks for credentials or payment.

The model only *extracts*. Code decides what it means (checks/page_llm.py): the model never compares domains and
never decides a verdict. Page text is untrusted, redacted, and wrapped in <untrusted_input>.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.ai.llm import INJECTION_RULES, LlmClient, LlmUnavailable

SYSTEM = (
    "You read the visible text of a web page and extract three facts about it. " + INJECTION_RULES + " "
    "claimed_brand: the organisation or product the page presents itself as (its own name, e.g. from the heading, "
    "logo text or title), or an empty string if it is not clear. Do not guess from the web address. "
    "seeks_credentials: the page asks the visitor for a password, PIN, OTP, card or account details. "
    "seeks_payment: the page asks the visitor to pay or send money. You do not judge whether the page is legitimate."
)


class BrandClaim(BaseModel):
    model_config = ConfigDict(extra="ignore")
    claimed_brand: str = Field(default="", max_length=80)
    seeks_credentials: bool = False
    seeks_payment: bool = False


async def extract_claim(llm: LlmClient, redacted_text: str) -> BrandClaim:
    """Raises LlmUnavailable on any LLM or validation failure."""
    raw = await llm.call_tool(system=SYSTEM, user=f"<untrusted_input>\n{redacted_text[:4000]}\n</untrusted_input>",
                              tool_name="report_page_claim", schema=BrandClaim.model_json_schema(), max_tokens=300)
    try:
        c = BrandClaim.model_validate(raw)
    except ValidationError:
        raise LlmUnavailable("llm output failed schema validation") from None
    clean = "".join(ch for ch in c.claimed_brand if ch.isprintable()).strip()
    return c.model_copy(update={"claimed_brand": clean})
