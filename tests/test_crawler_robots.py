"""robots.txt parsing and enforcement."""
from gandoki.crawl.fetcher import _RobotsRules


def test_allow_all_on_parse_failure():
    r = _RobotsRules.parse("garbage that doesn't parse", "UA")
    assert r.can_fetch("/anything")


def test_disallow_blocks():
    r = _RobotsRules.parse(
        "User-agent: *\nDisallow: /private/\n", "TestBot"
    )
    assert not r.can_fetch("/private/x")
    assert r.can_fetch("/public/x")


def test_allow_beats_disallow_on_tie():
    r = _RobotsRules.parse(
        "User-agent: *\nDisallow: /private/\nAllow: /private/ok\n",
        "TestBot",
    )
    assert r.can_fetch("/private/ok")
    assert not r.can_fetch("/private/no")


def test_longest_match_wins():
    r = _RobotsRules.parse(
        "User-agent: *\nDisallow: /a\nAllow: /a/b\n", "UA"
    )
    assert r.can_fetch("/a/b/c")
    assert not r.can_fetch("/a/x")


def test_crawl_delay_parsed():
    r = _RobotsRules.parse(
        "User-agent: *\nCrawl-delay: 2.5\n", "UA"
    )
    assert r.crawl_delay == 2.5


def test_ua_specific_block():
    r = _RobotsRules.parse(
        "User-agent: Gandoki\nDisallow: /\n\n"
        "User-agent: *\nAllow: /\n",
        "Gandoki/1.0",
    )
    assert not r.can_fetch("/anything")


def test_wildcard_fallback():
    r = _RobotsRules.parse(
        "User-agent: Googlebot\nDisallow: /\n\n"
        "User-agent: *\nAllow: /\n",
        "Gandoki/1.0",
    )
    assert r.can_fetch("/anything")
