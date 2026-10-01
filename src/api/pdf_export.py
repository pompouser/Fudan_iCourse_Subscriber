"""Shared, self-contained PDF rendering for subscriptions and manual exports."""

import base64
from html import escape


def safe_filename(title: str) -> str:
    return ("".join(c if c.isalnum() or c in " _-" else "_"
                    for c in title).strip()[:100] or "course")


def render_course_pdf(course_title: str, lectures: list[dict],
                      teacher: str = "") -> bytes:
    from weasyprint import HTML, default_url_fetcher
    from src.api.emailer import _md_to_html, _PYGMENTS_CSS

    images = {}
    sections = [f"<h1>{escape(course_title)}</h1>"]
    if teacher:
        sections.append(f"<p>任课教师：{escape(teacher)}</p>")
    for lec in lectures:
        title = escape(str(lec.get("sub_title", "")))
        date = escape(str(lec.get("date", "")))
        badge = "（更新）" if lec.get("is_update") else ""
        sections.append(f"<h2>{title}{badge}</h2><p class='date'>{date}</p>")
        sections.append(_md_to_html(lec["summary"], cid_images=images))
    body = "\n".join(sections)
    for cid, data in images.items():
        body = body.replace(f"cid:{cid}", "data:image/png;base64," +
                            base64.b64encode(data).decode("ascii"))

    # Only the already fetched formula images may be loaded by the renderer.
    # Raw HTML in a summary must never read local files or internal URLs.
    def fetch(url, *args, **kwargs):
        if not url.startswith("data:image/png;base64,"):
            raise ValueError("External PDF resources are disabled")
        return default_url_fetcher(url, *args, **kwargs)

    css = """
    @page { size: A4; margin: 19mm 17mm 20mm;
      @bottom-center { content: counter(page) ' / ' counter(pages);
        font-size: 9pt; color: #64748b; } }
    body { font-family: 'Noto Sans CJK SC', 'Microsoft YaHei', sans-serif;
      font-size: 10.5pt; line-height: 1.65; color: #243247;
      overflow-wrap: anywhere; }
    h1 { font-size: 23pt; color: #173c62; }
    h2 { font-size: 16pt; border-bottom: 1px solid #b8c8d8;
      margin-top: 22pt; padding-bottom: 5pt; }
    h3 { font-size: 13pt; }
    h1, h2, h3, h4 { break-after: avoid; }
    .date { color: #64748b; font-size: 9pt; break-after: avoid; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td { border: 1px solid #cbd5e1; padding: 5pt; }
    th { background: #eff4f8; } tr { break-inside: avoid; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere;
      background: #f3f5f7; padding: 8pt; font-size: 9pt; }
    code { font-family: monospace; }
    blockquote { border-left: 3px solid #6e92b4; margin-left: 0;
      padding-left: 12pt; color: #475569; }
    img { max-width: 100% !important; height: auto !important; }
    a { color: #215b8e; } p { orphans: 3; widows: 3; }
    """
    html = ("<!doctype html><html lang='zh-CN'><meta charset='utf-8'>"
            f"<style>{css}\n{_PYGMENTS_CSS}</style><body>{body}</body></html>")
    return HTML(string=html, url_fetcher=fetch).write_pdf()
