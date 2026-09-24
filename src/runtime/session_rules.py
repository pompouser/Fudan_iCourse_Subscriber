"""Private per-course schedule allowlists for lecture processing."""

from __future__ import annotations

import re
from datetime import date


SessionRule = tuple[int, int, int]
SessionRules = dict[str, frozenset[SessionRule] | None]

_WEEKDAYS = {
    "一": 0, "二": 1, "三": 2, "四": 3,
    "五": 4, "六": 5, "日": 6, "天": 6,
}
_RULE_RE = re.compile(
    r"周([一二三四五六日天])\s*第\s*(\d+)"
    r"(?:\s*[-—–~～至]\s*(\d+))?\s*节"
)
_PERIOD_RE = re.compile(
    r"第\s*(\d+)(?:\s*[-—–~～至]\s*(\d+))?\s*节"
)
_DATE_RE = re.compile(r"(\d{4})-(\d{1,2})-(\d{1,2})")


class SessionRulesError(ValueError):
    """Raised for malformed rules without echoing their secret contents."""


def parse_course_session_rules(raw: str) -> SessionRules:
    parsed: SessionRules = {}
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("=") != 1:
            raise SessionRulesError(
                f"Invalid COURSE_SESSION_RULES at line {line_number}"
            )
        course_id, selection = (part.strip() for part in line.split("=", 1))
        if not course_id or not selection or course_id in parsed:
            raise SessionRulesError(
                f"Invalid COURSE_SESSION_RULES at line {line_number}"
            )
        tokens = [part.strip() for part in re.split(r"[|｜]", selection)]
        if any(not token for token in tokens):
            raise SessionRulesError(
                f"Invalid COURSE_SESSION_RULES at line {line_number}"
            )
        if len(tokens) == 1 and tokens[0].upper() in {"全部", "ALL", "*"}:
            parsed[course_id] = None
            continue
        rules: set[SessionRule] = set()
        for token in tokens:
            match = _RULE_RE.fullmatch(token)
            if not match:
                raise SessionRulesError(
                    f"Invalid COURSE_SESSION_RULES at line {line_number}"
                )
            start = int(match.group(2))
            end = int(match.group(3) or start)
            if start < 1 or end < start:
                raise SessionRulesError(
                    f"Invalid COURSE_SESSION_RULES at line {line_number}"
                )
            rules.add((_WEEKDAYS[match.group(1)], start, end))
        parsed[course_id] = frozenset(rules)
    return parsed


def lecture_is_selected(
    course_id: str, lecture: dict, rules: SessionRules
) -> bool:
    course_id = str(course_id)
    if course_id not in rules or rules[course_id] is None:
        return True
    sub_title = str(lecture.get("sub_title") or "")
    date_text = str(lecture.get("date") or "")
    date_match = _DATE_RE.search(date_text) or _DATE_RE.search(sub_title)
    period_match = _PERIOD_RE.search(sub_title)
    if not date_match or not period_match:
        return False
    try:
        lecture_date = date(*(int(part) for part in date_match.groups()))
    except ValueError:
        return False
    start = int(period_match.group(1))
    end = int(period_match.group(2) or start)
    return (lecture_date.weekday(), start, end) in rules[course_id]
