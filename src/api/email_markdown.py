"""Build Markdown attachments for course-summary emails."""

from __future__ import annotations

import re


def build_course_markdown(course_title: str, lectures: list[dict]) -> str:
    parts = [f"# {course_title}"]
    for lecture in lectures:
        update = "（PPT 识别更新）" if lecture.get("is_update") else ""
        heading = f"## {lecture['sub_title']}{update}"
        parts.extend(["", heading])
        if lecture.get("date"):
            parts.extend(["", f"> 日期：{lecture['date']}"])
        parts.extend(["", str(lecture["summary"]).strip()])
    return "\n".join(parts).rstrip() + "\n"


def build_attachment_filename(course_title: str, lectures: list[dict]) -> str:
    safe_title = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", course_title)
    safe_title = safe_title.strip(" .")[:80] or "course-summary"
    dates = sorted({str(item.get("date") or "") for item in lectures} - {""})
    if not dates:
        suffix = "summary"
    elif len(dates) == 1:
        suffix = dates[0]
    else:
        suffix = f"{dates[0]}_to_{dates[-1]}"
    return f"{safe_title}_{suffix}.md"
