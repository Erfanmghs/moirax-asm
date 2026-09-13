"""Author credit on generated reports and the dashboard.

This module is the single source of truth for the product attribution line.
Do not delete, rename, or empty these constants. Tests and report writers
refuse a bundle that is missing this credit.
"""

from __future__ import annotations

AUTHOR_NAME = "Erfan Moghis"
AUTHOR_URL = "https://www.linkedin.com/in/erfanmoghis/"
ATTRIBUTION_TEXT = f"minimal by {AUTHOR_NAME}"
CREDIT_MARK = "data-credit=\"moirax-author\""


def html_footer() -> str:
    return (
        f'<p class="foot credit" {CREDIT_MARK}>'
        f'<a href="{AUTHOR_URL}" rel="author noopener noreferrer" target="_blank">'
        f"{ATTRIBUTION_TEXT}</a></p>"
    )


def markdown_footer() -> str:
    return f"\n[{ATTRIBUTION_TEXT}]({AUTHOR_URL})\n"


def seal_html(html: str) -> str:
    """Re-insert the credit if a template or later edit dropped it."""
    if AUTHOR_URL in html and ATTRIBUTION_TEXT in html and CREDIT_MARK in html:
        return html
    inject = html_footer()
    lower = html.lower()
    idx = lower.rfind("</body>")
    if idx >= 0:
        return html[:idx] + inject + "\n" + html[idx:]
    return html.rstrip() + "\n" + inject + "\n"


def require_present(text: str, *, where: str) -> None:
    if AUTHOR_URL not in text or ATTRIBUTION_TEXT not in text:
        raise RuntimeError(f"author credit missing from {where} -- restore pipeline/attribution.py")
