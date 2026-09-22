"""Offline PDF from canonical escaped HTML, with all resource URL fetches denied."""
from threading import BoundedSemaphore
from weasyprint import HTML
from backend.reporting.html import render

SLOT = BoundedSemaphore(1)
MAX_PDF_HTML = 256 * 1024


def deny_resource(url, *args, **kwargs):
    raise ValueError("PDF resource fetching is disabled")


def render_pdf(analysis, kind: str) -> bytes:
    content = render(analysis, kind)
    if len(content.encode()) > MAX_PDF_HTML:
        raise ValueError("Report exceeds PDF rendering limit; download canonical HTML")
    if not SLOT.acquire(blocking=False):
        raise RuntimeError("PDF renderer busy; retry shortly")
    try:
        # User strings are escaped by render(). No URLs, attachments, HTML or CSS are user-controlled.
        return HTML(string=content,url_fetcher=deny_resource).write_pdf()
    finally:
        SLOT.release()
