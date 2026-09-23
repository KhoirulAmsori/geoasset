import os
import sys
import time

import requests

from adapters.subscription import SubscriptionAdapter
from adapters.telegram import TelegramAdapter
from adapters.webpage import WebpageAdapter
from config import Config, load_config
from engine import run_collection
from state import ChannelState, load_state

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def load_lines(path: str) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    out: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
    return out


def http_get(session: requests.Session, url: str, timeout: int, retry: int) -> bytes | None:
    last_error: Exception | None = None
    for attempt in range(retry + 1):
        try:
            resp = session.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                return resp.content
            last_error = RuntimeError(f"status {resp.status_code}")
        except requests.RequestException as exc:
            last_error = exc
        if attempt < retry:
            time.sleep(min(2 ** attempt, 8))
    print(f"GET {url} failed: {last_error}", file=sys.stderr)
    return None


def fetch_telegram_page(
    session: requests.Session, cfg: Config, channel: str, before: int | None
) -> str | None:
    url = f"https://t.me/s/{channel}"
    if before is not None:
        url += f"?before={before}"
    body = http_get(session, url, cfg.timeout, cfg.http_retry)
    if body is None:
        return None
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("latin-1")


def main(argv: list[str] | None = None) -> int:
    cfg = load_config()
    session = requests.Session()

    state = load_state(cfg.channels_state_file)
    seed = load_lines(cfg.seed_file)
    channels = sorted(set(seed) | set(state.channels))
    states = {
        name: state.channels.get(name, ChannelState())
        for name in channels
    }

    def log(msg: str) -> None:
        print(msg, flush=True)

    telegram = TelegramAdapter(
        channels,
        states,
        lambda ch, before: fetch_telegram_page(session, cfg, ch, before),
        cfg,
        log=log,
    )
    subscriptions = SubscriptionAdapter(
        load_lines(cfg.subscriptions_file),
        lambda url: http_get(session, url, cfg.timeout, cfg.http_retry),
        cfg,
        log=log,
    )
    webpages = WebpageAdapter(
        load_lines(cfg.webpages_file),
        lambda url: http_get(session, url, cfg.timeout, cfg.http_retry),
        cfg,
        log=log,
    )

    return run_collection(cfg, [telegram, subscriptions, webpages], log=log)


if __name__ == "__main__":
    sys.exit(main())
