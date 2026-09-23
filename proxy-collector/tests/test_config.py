import config


def test_env_or_default(monkeypatch):
    monkeypatch.delenv("SomeKey", raising=False)
    assert config.env_or("SomeKey", "fallback") == "fallback"


def test_env_or_uses_env(monkeypatch):
    monkeypatch.setenv("SomeKey", "value")
    assert config.env_or("SomeKey", "fallback") == "value"


def test_env_or_ignores_blank(monkeypatch):
    monkeypatch.setenv("SomeKey", "   ")
    assert config.env_or("SomeKey", "fallback") == "fallback"


def test_env_int(monkeypatch):
    monkeypatch.setenv("SomeNum", "42")
    assert config.env_int("SomeNum", 1) == 42


def test_env_int_bad_value(monkeypatch):
    monkeypatch.setenv("SomeNum", "nope")
    assert config.env_int("SomeNum", 7) == 7


def test_load_config_defaults(monkeypatch):
    for k in ("CollectedFile", "ChannelsStateFile", "SeedFile",
              "SubscriptionsFile", "WebpagesFile", "TelegramDepth",
              "Concurrency", "Timeout", "HttpRetry", "MaxNewChannels",
              "MinCollected", "SkipPushFlag"):
        monkeypatch.delenv(k, raising=False)
    cfg = config.load_config()
    assert cfg.collected_file == "collected.txt"
    assert cfg.channels_state_file == "channels.json"
    assert cfg.seed_file == "channels_seed.txt"
    assert cfg.subscriptions_file == "subscriptions.txt"
    assert cfg.webpages_file == "webpages.txt"
    assert cfg.telegram_depth == 3
    assert cfg.concurrency == 8
    assert cfg.timeout == 15
    assert cfg.http_retry == 2
    assert cfg.max_new_channels == 50
    assert cfg.min_collected == 0
    assert cfg.skip_push_flag == "skip_push.flag"


def test_load_config_overrides(monkeypatch):
    monkeypatch.setenv("TelegramDepth", "5")
    monkeypatch.setenv("Concurrency", "16")
    cfg = config.load_config()
    assert cfg.telegram_depth == 5
    assert cfg.concurrency == 16
