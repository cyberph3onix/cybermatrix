"""Guess what the user submitted. Mirrors frontend/lib/detect.ts; the API honours an explicit subject_type."""
from __future__ import annotations

import re

from app.schemas import SubjectType

_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
_URL = re.compile(r"^https?://\S+$", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\.?(?::\d+)?(?:[/?#]\S*)?$", re.IGNORECASE)


def detect_subject(raw: str) -> SubjectType:
    text = raw.strip()
    if re.search(r"\s", text):
        return SubjectType.MESSAGE
    if _EMAIL.match(text):
        return SubjectType.EMAIL
    if _URL.match(text):
        return SubjectType.URL
    if _DOMAIN.match(text):
        return SubjectType.URL if re.search(r"[/?#]", text) else SubjectType.DOMAIN
    return SubjectType.MESSAGE
