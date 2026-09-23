import base64

from adapters.webpage import WebpageAdapter, html_to_text, parse_webpage
from config import Config


def make_cfg():
    return Config(
        collected_file="c", channels_state_file="s", seed_file="seed",
        subscriptions_file="sub", webpages_file="web", telegram_depth=3,
        concurrency=8, timeout=15, http_retry=2, max_new_channels=50,
        min_collected=0, skip_push_flag="skip",
    )


def test_html_to_text_preserves_lines():
    html = "<p>vless://a@1.2.3.4:443#A</p><p>vless://b@2.2.2.2:443#B</p>"
    text = html_to_text(html)
    assert "vless://a@1.2.3.4:443#A" in text
    assert "vless://b@2.2.2.2:443#B" in text


def test_parse_webpage_extracts_configs():
    html = "<html><body><code>vless://a@1.2.3.4:443#A</code></body></html>"
    assert parse_webpage(html.encode()) == ["vless://a@1.2.3.4:443#A"]


def test_parse_webpage_unescapes_amp():
    html = "<div>vless://a@1.2.3.4:443?type=ws&amp;security=tls#A</div>"
    assert parse_webpage(html.encode()) == [
        "vless://a@1.2.3.4:443?type=ws&security=tls#A"
    ]


def test_parse_webpage_falls_back_to_base64_body():
    plain = "vless://a@1.2.3.4:443#A"
    body = base64.b64encode(plain.encode()).decode().encode()
    assert parse_webpage(body) == ["vless://a@1.2.3.4:443#A"]


def test_adapter_collects_and_reports_errors():
    def fetch(url):
        if url == "good":
            return b"<code>vless://a@1.2.3.4:443#A</code>"
        return None

    adapter = WebpageAdapter(["good", "bad"], fetch, make_cfg())
    res = adapter.fetch()
    assert res.configs == ["vless://a@1.2.3.4:443#A"]
    assert any("bad" in e for e in res.errors)
