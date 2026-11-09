"""Two-sentence AI summary of a cluster. The LLM only describes structured facts; it decides nothing."""
from __future__ import annotations

import asyncio
import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.ai.explain import _PRODUCT, _SAFE
from app.ai.llm import INJECTION_RULES, LlmClient, LlmUnavailable
from app.schemas import Cluster

SYSTEM = (
    "You describe a cluster of web-threat reports that share an indicator, in exactly two plain sentences for a "
    "non-technical reader. " + INJECTION_RULES + " Use only the facts given. A shared indicator suggests, but does "
    "not prove, a common operator: say 'may' or 'suggests'. Do not name people. Do not give advice."
)
MAX_PER_REQUEST = 10


class SummaryOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    summary: str = Field(max_length=500)


def facts(c: Cluster) -> dict:
    return {"reports": len(c.report_ids), "worst_class": str(c.top_classification),
            "first_seen": c.first_seen.date().isoformat(), "last_seen": c.last_seen.date().isoformat(),
            "shared": [{"type": i.type, "in_reports": i.report_count} for i in c.shared_indicators[:6]],
            "domains": c.member_domains[:6]}


def cache_key(c: Cluster) -> str:
    return c.cluster_id + ":" + hashlib.sha256("|".join(c.report_ids).encode()).hexdigest()[:10]


async def summarize_one(llm: LlmClient, c: Cluster) -> str:
    raw = await llm.call_tool(system=SYSTEM, user=f"<untrusted_input>\n{json.dumps(facts(c))}\n</untrusted_input>",
                              tool_name="cluster_summary", schema=SummaryOut.model_json_schema(), max_tokens=300)
    try:
        text = SummaryOut.model_validate(raw).summary.strip()
    except ValidationError:
        raise LlmUnavailable("llm output failed schema validation") from None
    if not text or _SAFE.search(_PRODUCT.sub("", text)):  # rule 3
        raise LlmUnavailable("summary rejected")
    return text


async def add_summaries(llm: LlmClient | None, clusters: list[Cluster], cache: dict[str, str]) -> list[Cluster]:
    """Attach summaries from the cache, generating at most MAX_PER_REQUEST new ones. Failures leave it null."""
    if llm is None:
        return clusters
    todo = [c for c in clusters if cache_key(c) not in cache][:MAX_PER_REQUEST]

    async def one(c: Cluster) -> None:
        try:
            cache[cache_key(c)] = await asyncio.wait_for(summarize_one(llm, c), 25)
        except (LlmUnavailable, TimeoutError):
            pass

    await asyncio.gather(*(one(c) for c in todo))
    return [c.model_copy(update={"summary": cache[cache_key(c)], "summary_model": llm.model})
            if cache_key(c) in cache else c for c in clusters]
