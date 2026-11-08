# -*- coding: utf-8 -*-
"""过滤规则引擎测试（AdGuard 语法子集）。"""

import unittest

from core.dns_rules import RuleSet, compile_rules, normalize_domain, parse_filter_list


class TestNormalizeDomain(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(normalize_domain(" Example.COM. "), "example.com")
        self.assertEqual(normalize_domain("*.ads.com"), "ads.com")
        self.assertEqual(normalize_domain(".ads.com"), "ads.com")
        self.assertEqual(normalize_domain(""), "")

    def test_invalid(self):
        self.assertEqual(normalize_domain("no-dot"), "")
        self.assertEqual(normalize_domain("has space.com"), "")
        self.assertEqual(normalize_domain("http://a.com"), "")


class TestPlainDomain(unittest.TestCase):
    def test_domain_and_subdomain(self):
        rs = RuleSet()
        rs.add_line("ads.example.com")
        self.assertTrue(rs.is_blocked("ads.example.com"))
        self.assertTrue(rs.is_blocked("cdn.ads.example.com"))
        self.assertFalse(rs.is_blocked("example.com"))
        self.assertFalse(rs.is_blocked("notads.example.com"))

    def test_wildcard_prefix(self):
        rs = RuleSet()
        rs.add_line("*.tracker.com")
        self.assertTrue(rs.is_blocked("tracker.com"))
        self.assertTrue(rs.is_blocked("x.y.tracker.com"))

    def test_rule_text_is_reported(self):
        rs = RuleSet()
        rs.add_line("ads.example.com")
        blocked, rule = rs.match("a.ads.example.com")
        self.assertTrue(blocked)
        self.assertEqual(rule, "||ads.example.com^")


class TestHostsLines(unittest.TestCase):
    def test_single(self):
        rs = RuleSet()
        rs.add_line("0.0.0.0 ads.com")
        self.assertTrue(rs.is_blocked("ads.com"))
        self.assertTrue(rs.is_blocked("img.ads.com"))

    def test_multiple_domains_in_one_line(self):
        rs = RuleSet()
        rs.add_line("127.0.0.1 a.com b.com :: c.com")
        for d in ("a.com", "b.com", "c.com"):
            self.assertTrue(rs.is_blocked(d), d)

    def test_inline_comment(self):
        rs = RuleSet()
        rs.add_line("0.0.0.0 ads.com # 广告")
        self.assertTrue(rs.is_blocked("ads.com"))


class TestAbpSyntax(unittest.TestCase):
    def test_suffix_anchor(self):
        rs = RuleSet()
        rs.add_line("||doubleclick.net^")
        self.assertTrue(rs.is_blocked("doubleclick.net"))
        self.assertTrue(rs.is_blocked("ad.g.doubleclick.net"))

    def test_exception_wins(self):
        rs = RuleSet()
        rs.add_line("||example.com^")
        rs.add_line("@@||cdn.example.com^")
        self.assertTrue(rs.is_blocked("www.example.com"))
        self.assertFalse(rs.is_blocked("cdn.example.com"))
        self.assertFalse(rs.is_blocked("static.cdn.example.com"))
        self.assertIn("@@", rs.match("cdn.example.com")[1])

    def test_url_rule(self):
        rs = RuleSet()
        rs.add_line("|https://banner.example.com/path?x=1")
        self.assertTrue(rs.is_blocked("banner.example.com"))

    def test_modifier_ignored(self):
        rs = RuleSet()
        rs.add_line("||ads.com^$third-party")
        self.assertTrue(rs.is_blocked("ads.com"))


class TestRegex(unittest.TestCase):
    def test_block_regex(self):
        rs = RuleSet()
        rs.add_line(r"/^ads?\d+\.example\.com$/")
        self.assertTrue(rs.is_blocked("ad1.example.com"))
        self.assertTrue(rs.is_blocked("ads22.example.com"))
        self.assertFalse(rs.is_blocked("adx.example.com"))

    def test_allow_regex(self):
        rs = RuleSet()
        rs.add_line(r"/tracker/")
        rs.add_line(r"@@/^oktracker/")
        self.assertTrue(rs.is_blocked("tracker.a.com"))
        self.assertFalse(rs.is_blocked("oktracker.a.com"))

    def test_broken_regex_ignored(self):
        rs = RuleSet()
        rs.add_line("/[unclosed/")
        self.assertEqual(rs.count, 0)
        self.assertGreaterEqual(rs.invalid, 1)


class TestCompileAndComments(unittest.TestCase):
    def test_comments_and_blank(self):
        text = "\n".join([
            "# 主注释",
            "! adblock 注释",
            "",
            "||ads.com^",
            "   ",
            "@@||ok.ads.com^",
        ])
        rs = compile_rules(text)
        self.assertTrue(rs.is_blocked("ads.com"))
        self.assertFalse(rs.is_blocked("ok.ads.com"))
        self.assertEqual(rs.count, 2)

    def test_multi_group(self):
        rs = compile_rules(["a.com", "b.com"], ["@@b.com"])
        self.assertTrue(rs.is_blocked("a.com"))
        self.assertFalse(rs.is_blocked("b.com"))
        self.assertEqual(rs.count, 3)

    def test_parse_filter_list_strips(self):
        rules = parse_filter_list("# c\n\n0.0.0.0 a.com\n||b.com^\n")
        self.assertEqual(rules, ["0.0.0.0 a.com", "||b.com^"])

    def test_allow_count(self):
        rs = RuleSet()
        rs.add_line("@@||a.com^")
        rs.add_line("@@||b.com^")
        rs.add_line("||c.com^")
        self.assertEqual(rs.allow_count, 2)
        self.assertEqual(rs.suffix_count, 1)


if __name__ == "__main__":
    unittest.main()
