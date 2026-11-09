"""Deterministic detector for text aimed at automated systems. Not delegated to the LLM."""
from __future__ import annotations

import re

_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"ignore (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions|prompts?|rules)",
    r"disregard (?:all |any |the )?(?:previous|prior|above|your) (?:instructions|prompts?|rules)",
    r"(?:mark|label|classify|rate|report|say|state)\b[^.\n]{0,40}\b(?:as |it as |this as )?(?:safe|legit(?:imate)?|harmless|not (?:a )?(?:scam|phishing))",
    r"\b(?:system prompt|developer message|you are (?:now )?(?:an? )?(?:ai|assistant|language model|chatbot))\b",
    r"(?:note|message) to (?:the )?(?:ai|assistant|llm|scanner|analy[sz]er|model)",
    r"\b(?:jailbreak|prompt injection|new instructions?)\b",
)]


def has_injection(text: str) -> bool:
    return any(p.search(text) for p in _PATTERNS)
