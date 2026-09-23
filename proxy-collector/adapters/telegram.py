import re
from dataclasses import dataclass

from bs4 import BeautifulSoup

DISCOVER_RE = re.compile(
    r"(?:@|%40|t\.me/|telegram\.me/)([A-Za-z0-9_]{5,})",
    re.IGNORECASE,
)


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
    return [m.group(1) for m in DISCOVER_RE.finditer(text)]
