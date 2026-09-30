"""Moved to mailwarden.core.html_text (shared by providers and job-description parsing)."""

from mailwarden.core.html_text import HtmlParseError, html_links, html_to_text, looks_like_html

__all__ = ["HtmlParseError", "html_links", "html_to_text", "looks_like_html"]
