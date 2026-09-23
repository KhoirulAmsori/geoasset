import os
from dataclasses import dataclass


def env_or(key: str, default: str) -> str:
    value = os.environ.get(key)
    if value is not None and value.strip() != "":
        return value.strip()
    return default


def env_int(key: str, default: int) -> int:
    value = os.environ.get(key)
    if value is not None:
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


@dataclass
class Config:
    collected_file: str
    channels_state_file: str
    seed_file: str
    subscriptions_file: str
    webpages_file: str
    telegram_depth: int
    concurrency: int
    timeout: int
    http_retry: int
    max_new_channels: int
    min_collected: int
    skip_push_flag: str


def load_config() -> Config:
    cfg = Config(
        collected_file=env_or("CollectedFile", "collected.txt"),
        channels_state_file=env_or("ChannelsStateFile", "channels.json"),
        seed_file=env_or("SeedFile", "channels_seed.txt"),
        subscriptions_file=env_or("SubscriptionsFile", "subscriptions.txt"),
        webpages_file=env_or("WebpagesFile", "webpages.txt"),
        telegram_depth=env_int("TelegramDepth", 3),
        concurrency=env_int("Concurrency", 8),
        timeout=env_int("Timeout", 15),
        http_retry=env_int("HttpRetry", 2),
        max_new_channels=env_int("MaxNewChannels", 50),
        min_collected=env_int("MinCollected", 0),
        skip_push_flag=env_or("SkipPushFlag", "skip_push.flag"),
    )
    if cfg.telegram_depth < 1:
        cfg.telegram_depth = 1
    if cfg.concurrency < 1:
        cfg.concurrency = 1
    if cfg.http_retry < 0:
        cfg.http_retry = 0
    return cfg
