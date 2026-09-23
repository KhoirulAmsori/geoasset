import main


def test_load_lines_skips_blank_and_comments(tmp_path):
    p = tmp_path / "list.txt"
    p.write_text("# comment\n\n  hope_net \n#x\nv2ray_ng\n", encoding="utf-8")
    assert main.load_lines(str(p)) == ["hope_net", "v2ray_ng"]


def test_load_lines_missing_file(tmp_path):
    assert main.load_lines(str(tmp_path / "nope.txt")) == []


def test_telegram_url_without_cursor(monkeypatch):
    captured = {}

    class FakeResp:
        content = b"<html></html>"
        status_code = 200

    class FakeSession:
        def get(self, url, timeout=None, headers=None):
            captured["url"] = url
            return FakeResp()

    cfg = main.load_config()
    main.fetch_telegram_page(FakeSession(), cfg, "hope_net", None)
    assert captured["url"] == "https://t.me/s/hope_net"


def test_telegram_url_with_cursor():
    captured = {}

    class FakeResp:
        content = b"<html></html>"
        status_code = 200

    class FakeSession:
        def get(self, url, timeout=None, headers=None):
            captured["url"] = url
            return FakeResp()

    cfg = main.load_config()
    main.fetch_telegram_page(FakeSession(), cfg, "hope_net", 123)
    assert captured["url"] == "https://t.me/s/hope_net?before=123"


def test_build_adapters_skips_empty_sources(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "channels_seed.txt").write_text("", encoding="utf-8")
    (tmp_path / "subscriptions.txt").write_text("# none\n", encoding="utf-8")
    (tmp_path / "webpages.txt").write_text("# none\n", encoding="utf-8")
    monkeypatch.setenv("SeedFile", "channels_seed.txt")
    monkeypatch.setenv("SubscriptionsFile", "subscriptions.txt")
    monkeypatch.setenv("WebpagesFile", "webpages.txt")
    cfg = main.load_config()
    adapters = main.build_adapters(cfg, object(), [], {}, lambda m: None)
    assert adapters == []


def test_build_adapters_includes_only_sources_with_urls(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "channels_seed.txt").write_text("hope_net\n", encoding="utf-8")
    (tmp_path / "subscriptions.txt").write_text("# none\n", encoding="utf-8")
    (tmp_path / "webpages.txt").write_text("https://example.com\n", encoding="utf-8")
    monkeypatch.setenv("SeedFile", "channels_seed.txt")
    monkeypatch.setenv("SubscriptionsFile", "subscriptions.txt")
    monkeypatch.setenv("WebpagesFile", "webpages.txt")
    cfg = main.load_config()
    adapters = main.build_adapters(cfg, object(), ["hope_net"], {}, lambda m: None)
    assert len(adapters) == 2
