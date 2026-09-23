from typing import Callable

from bs4 import BeautifulSoup

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


def html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(separator="\n")


def parse_webpage(body: bytes) -> list[str]:
    text = _as_text(body)
    decoded = decode_base64(text)
    if decoded is not None and "://" in decoded and "<" not in decoded:
        return extract_configs(decoded)
    return extract_configs(html_to_text(text))


class WebpageAdapter:
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
            configs = parse_webpage(body)
            self.log(f"webpage {url}: {len(configs)} configs")
            result.configs.extend(configs)
        return result
