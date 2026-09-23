import base64

from adapters.subscription import SubscriptionAdapter, decode_body, parse_subscription
from config import Config


def make_cfg():
    return Config(
        collected_file="c", channels_state_file="s", seed_file="seed",
        subscriptions_file="sub", webpages_file="web", telegram_depth=3,
        concurrency=8, timeout=15, http_retry=2, max_new_channels=50,
        min_collected=0, skip_push_flag="skip", retire_after=10, retry_after=30,
    )


def test_decode_plaintext():
    body = b"vless://a@1.2.3.4:443#A\n"
    assert decode_body(body) == "vless://a@1.2.3.4:443#A\n"


def test_decode_base64_body():
    plain = "vless://a@1.2.3.4:443#A\nvless://b@2.2.2.2:443#B"
    body = base64.b64encode(plain.encode()).decode().encode()
    assert decode_body(body) == plain


def test_decode_base64_without_padding():
    plain = "vless://a@1.2.3.4:443#A"
    body = base64.b64encode(plain.encode()).decode().rstrip("=").encode()
    assert decode_body(body) == plain


def test_plaintext_that_looks_like_base64_is_not_corrupted():
    # This string is valid base64 alphabet, but decodes to non-config bytes.
    body = b"aGVsbG8gd29ybGQ="  # "hello world"
    assert decode_body(body) == "aGVsbG8gd29ybGQ="


def test_parse_subscription_base64():
    plain = "vless://a@1.2.3.4:443#A\nvless://b@2.2.2.2:443#B"
    body = base64.b64encode(plain.encode()).decode().encode()
    assert parse_subscription(body) == [
        "vless://a@1.2.3.4:443#A",
        "vless://b@2.2.2.2:443#B",
    ]


def test_adapter_collects_from_all_urls_and_reports_errors():
    def fetch(url):
        if url == "good":
            return b"vless://a@1.2.3.4:443#A"
        return None

    adapter = SubscriptionAdapter(["good", "bad"], fetch, make_cfg())
    res = adapter.fetch()
    assert res.configs == ["vless://a@1.2.3.4:443#A"]
    assert any("bad" in e for e in res.errors)
    assert res.state_updates == {}
