"""Polite page fetching for job descriptions: robots.txt and a per-site pace. No network code here.

``PageFetcher.get_page(url)`` is the ``get_page`` that ``jd.acquire`` calls. Before a site's
first page it reads that site's robots.txt (through the same guarded session) and refuses
pages the site asks robots not to fetch, under the user agent "mailwarden" (RFC 9309: a
missing robots.txt allows everything; an unreachable one or a server error allows nothing).
Requests to the same site are at least ``min_interval`` seconds apart, robots.txt included.
"""

from __future__ import annotations

import time
import urllib.robotparser
from collections.abc import Callable
from urllib.parse import urlsplit

GetPage = Callable[[str], tuple[int, str]]  # (status, html)
GetRobots = Callable[[str], tuple[int, str]]  # (status, robots.txt text)

ROBOTS_AGENT = "mailwarden"


class PageRefused(Exception):
    """We chose not to fetch the page (robots.txt); the message says why."""


class PageFetcher:
    def __init__(self, get_page: GetPage, get_robots: GetRobots, *, min_interval: float = 5.0,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        self._get_page = get_page
        self._get_robots = get_robots
        self._min_interval = min_interval
        self._clock = clock
        self._sleep = sleep
        self._robots: dict[str, urllib.robotparser.RobotFileParser | bool] = {}
        self._last: dict[str, float] = {}

    def _pace(self, host: str) -> None:
        last = self._last.get(host)
        if last is not None:
            wait = self._min_interval - (self._clock() - last)
            if wait > 0:
                self._sleep(wait)
        self._last[host] = self._clock()

    def _rules(self, scheme: str, host: str) -> urllib.robotparser.RobotFileParser | bool:
        """A parser, True (no robots.txt: allow all) or False (unreachable/server error: allow nothing)."""
        if host not in self._robots:
            self._pace(host)
            try:
                status, text = self._get_robots(f"{scheme}://{host}/robots.txt")
            except Exception:
                status, text = 0, ""
            if status == 200:
                parser = urllib.robotparser.RobotFileParser()
                parser.parse(text.splitlines()[:5000])
                self._robots[host] = parser
            else:
                self._robots[host] = 400 <= status < 500
        return self._robots[host]

    def allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        rules = self._rules(parts.scheme, (parts.hostname or "").lower())
        if isinstance(rules, bool):
            return rules
        return rules.can_fetch(ROBOTS_AGENT, url)

    def get_page(self, url: str) -> tuple[int, str]:
        if not self.allowed(url):
            raise PageRefused("the site's robots.txt asks not to fetch this page")
        self._pace((urlsplit(url).hostname or "").lower())
        return self._get_page(url)
