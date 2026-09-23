import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from bs4 import BeautifulSoup

from adapters.base import FetchResult
from config import Config
from extract import extract_configs
from state import STATUS_ACTIVE, STATUS_INVALID, ChannelState

DISCOVER_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:@|%40|t\.me/|telegram\.me/)([A-Za-z0-9_]{5,})",
    re.IGNORECASE,
)

BLACKLISTED_HANDLES = {
    "joinchat", "addstickers", "telegram", "share", "iv", "s", "proxy",
    "socks", "mtproto", "telegrambot", "gmail", "youtube", "twitter",
    "facebook", "instagram", "github",
}
BLACKLISTED_SUFFIXES = ("_bot",)


@dataclass
class Message:
    id: int
    text: str


def parse_messages(html: str) -> list[Message]:
    soup = BeautifulSoup(html, "html.parser")
    out: list[Message] = []
    for node in soup.select("div.tgme_widget_message"):
        post = node.get("data-post", "")
        if "/" not in post:
            continue
        try:
            mid = int(post.rsplit("/", 1)[1])
        except ValueError:
            continue
        text_node = node.select_one(".tgme_widget_message_text")
        text = text_node.get_text(separator="\n") if text_node else ""
        out.append(Message(mid, text))
    out.sort(key=lambda m: m.id)
    return out


def discover_usernames(text: str) -> list[str]:
    out: list[str] = []
    for match in DISCOVER_RE.finditer(text):
        name = match.group(1).lower()
        if name in BLACKLISTED_HANDLES:
            continue
        if name.endswith(BLACKLISTED_SUFFIXES):
            continue
        out.append(name)
    return out


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class _ChannelOutcome:
    name: str
    configs: list[str]
    candidates: list[str]
    state: ChannelState
    error: str


class TelegramAdapter:
    def __init__(
        self,
        channels: list[str],
        states: dict[str, ChannelState],
        fetch_page: Callable[[str, int | None], str | None],
        cfg: Config,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.channels = channels
        self.states = states
        self.fetch_page = fetch_page
        self.cfg = cfg
        self.log = log or (lambda _msg: None)
        self.known = set(channels) | set(states)

    def fetch(self) -> FetchResult:
        result = FetchResult()

        outcomes = self._run_parallel(
            [(name, self.states.get(name, ChannelState())) for name in self.channels]
        )
        candidates: list[str] = []
        for outcome in outcomes:
            result.configs.extend(outcome.configs)
            result.state_updates[outcome.name] = outcome.state
            if outcome.error:
                result.errors.append(outcome.error)
            candidates.extend(outcome.candidates)

        fresh: list[str] = []
        for raw_name in candidates:
            name = raw_name.lower()
            if name in self.known:
                continue
            self.known.add(name)
            if len(fresh) >= self.cfg.max_new_channels:
                result.state_updates.setdefault(name, ChannelState(0, STATUS_ACTIVE, ""))
                continue
            fresh.append(name)

        backfill = self._run_parallel([(name, ChannelState()) for name in fresh])
        for outcome in backfill:
            self.log(f"discovered new channel: {outcome.name}")
            result.discovered.append(outcome.name)
            result.configs.extend(outcome.configs)
            result.state_updates[outcome.name] = outcome.state
            if outcome.error:
                result.errors.append(outcome.error)

        return result

    def _run_parallel(
        self, items: list[tuple[str, ChannelState]]
    ) -> list[_ChannelOutcome]:
        if not items:
            return []
        workers = min(self.cfg.concurrency, len(items))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(lambda item: self._process(*item), items))

    def _process(self, name: str, state: ChannelState) -> _ChannelOutcome:
        last = state.last_id
        before: int | None = None
        max_id = last
        pages = 0
        seen_any = False
        failed = False
        configs: list[str] = []
        candidates: list[str] = []

        while pages < self.cfg.telegram_depth:
            html = self.fetch_page(name, before)
            pages += 1
            if html is None:
                failed = True
                break
            msgs = parse_messages(html)
            if not msgs:
                break
            seen_any = True
            page_min = min(m.id for m in msgs)
            page_max = max(m.id for m in msgs)
            if page_max > max_id:
                max_id = page_max
            for m in msgs:
                if m.id > last:
                    configs.extend(extract_configs(m.text))
                    candidates.extend(discover_usernames(m.text))
            if page_min <= last:
                break
            before = page_min

        if failed:
            if seen_any and max_id > last:
                error = f"{name}: partial fetch failed after progress"
                return _ChannelOutcome(
                    name, configs, candidates, ChannelState(max_id, STATUS_ACTIVE, _now_iso()), error
                )
            return _ChannelOutcome(name, configs, candidates, ChannelState(last, STATUS_INVALID, ""), f"{name}: fetch failed")
        if not seen_any:
            return _ChannelOutcome(name, configs, candidates, ChannelState(last, STATUS_INVALID, ""), "")
        return _ChannelOutcome(
            name, configs, candidates, ChannelState(max_id, STATUS_ACTIVE, _now_iso()), ""
        )
