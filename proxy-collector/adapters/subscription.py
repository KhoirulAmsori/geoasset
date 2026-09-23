from typing import Callable

from adapters.base import FetchResult
from config import Config
from extract import decode_base64, extract_configs


def _as_text(body: bytes) -> str:
    if isinstance(body, bytes):
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.decode("latin-1")
    return str(body)


def decode_body(body: bytes) -> str:
    text = _as_text(body)
    decoded = decode_base64(text)
    if decoded is not None and "://" in decoded:
        return decoded
    return text


def parse_subscription(body: bytes) -> list[str]:
    return extract_configs(decode_body(body))


class SubscriptionAdapter:
    def __init__(
        self,
        urls: list[str],
        fetch_url: Callable[[str], bytes | None],
        cfg: Config,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.urls = urls
        self.fetch_url = fetch_url
        self.cfg = cfg
        self.log = log or (lambda _msg: None)

    def fetch(self) -> FetchResult:
        result = FetchResult()
        for url in self.urls:
            body = self.fetch_url(url)
            if body is None:
                result.errors.append(f"{url}: fetch failed")
                continue
            configs = parse_subscription(body)
            self.log(f"subscription {url}: {len(configs)} configs")
            result.configs.extend(configs)
        return result
