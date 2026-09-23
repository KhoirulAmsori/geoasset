from extract import clean_config, decode_base64, dedupe_sorted, extract_configs


def test_extracts_single_config():
    text = "server: vless://uuid@1.2.3.4:443?type=ws#Node"
    assert extract_configs(text) == ["vless://uuid@1.2.3.4:443?type=ws#Node"]


def test_extracts_multiple_schemes():
    text = (
        "vless://a@1.1.1.1:443#A\n"
        "trojan://b@2.2.2.2:443#B\n"
        "ss://YWVzOnh4@3.3.3.3:8388#C\n"
        "hysteria2://d@4.4.4.4:443#D\n"
    )
    got = extract_configs(text)
    assert got == [
        "vless://a@1.1.1.1:443#A",
        "trojan://b@2.2.2.2:443#B",
        "ss://YWVzOnh4@3.3.3.3:8388#C",
        "hysteria2://d@4.4.4.4:443#D",
    ]


def test_unescapes_html_ampersand():
    text = "vless://a@1.2.3.4:443?type=ws&amp;security=tls#A"
    assert extract_configs(text) == ["vless://a@1.2.3.4:443?type=ws&security=tls#A"]


def test_strips_telegram_truncation_markers():
    assert clean_config("vless://a@1.2.3.4:443#A…") == "vless://a@1.2.3.4:443#A"
    assert clean_config("vless://a@1.2.3.4:443#A»") == "vless://a@1.2.3.4:443#A"
    assert clean_config("vless://a@1.2.3.4:443#A`") == "vless://a@1.2.3.4:443#A"


def test_removes_encoded_newlines_and_replacement_char():
    text = "vless://a@1.2.3.4:443%0A#A\ufffd"
    assert extract_configs(text) == ["vless://a@1.2.3.4:443#A"]


def test_does_not_split_comma_inside_query():
    text = "vless://a@1.2.3.4:443?path=/x,y&host=z#A"
    assert extract_configs(text) == ["vless://a@1.2.3.4:443?path=/x,y&host=z#A"]


def test_splits_multiple_configs_joined_by_comma():
    text = "vless://a@1.1.1.1:443#A,trojan://b@2.2.2.2:443#B"
    assert extract_configs(text) == [
        "vless://a@1.1.1.1:443#A",
        "trojan://b@2.2.2.2:443#B",
    ]


def test_ignores_non_config_lines():
    text = "hello world\nhttps://example.com/page\n\nvless://a@1.2.3.4:443#A"
    assert extract_configs(text) == ["vless://a@1.2.3.4:443#A"]


def test_drops_config_without_host():
    assert extract_configs("vless://#onlyfragment") == []


def test_drops_too_short_config():
    assert extract_configs("ss://abc") == []


def test_decode_base64_valid():
    assert decode_base64("dmxlc3M6Ly9hQDEuMi4zLjQ6NDQzI0E=") == "vless://a@1.2.3.4:443#A"


def test_decode_base64_plaintext_returns_none():
    assert decode_base64("vless://a@1.2.3.4:443#A") is None


def test_dedupe_sorted():
    assert dedupe_sorted(["b", "a", "b", "c"]) == ["a", "b", "c"]
