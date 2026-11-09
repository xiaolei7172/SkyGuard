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


class TestBlockDomainsExport(unittest.TestCase):
    """DNS 规则 → 内核 rule-provider（behavior: domain）的域名导出。"""

    def test_suffix_exported_with_plus(self):
        rs = RuleSet()
        rs.add_line("||ads.example.com^")
        self.assertIn("+.ads.example.com", rs.block_domains())

    def test_exact_exported_plain(self):
        rs = RuleSet()
        rs.add_line("0.0.0.0 tracker.example.net")
        self.assertIn("tracker.example.net", rs.block_domains())

    def test_allow_exception_not_exported(self):
        rs = RuleSet()
        rs.add_line("||example.com^")
        rs.add_line("@@||ok.example.com^")
        domains = rs.block_domains()
        self.assertIn("+.example.com", domains)
        self.assertNotIn("+.ok.example.com", domains)

    def test_regex_not_exported(self):
        rs = RuleSet()
        rs.add_line("/ad[0-9]+\\.example\\.com/")
        self.assertEqual(rs.block_domains(), [])

    def test_limit_respected(self):
        rs = RuleSet()
        for i in range(30):
            rs.add_line(f"||d{i}.example.com^")
        self.assertEqual(len(rs.block_domains(limit=10)), 10)


class TestStrictDnsMode(unittest.TestCase):
    """strict 模式：DNS 层无法表达的作用域 / 路径规则必须跳过。

    背景：天影白名单里有 `@@||cloudflare.com/cdn-cgi/trace$domain=x` 这类规则，
    去掉 $domain 会变成「整域放行 cloudflare.com」，等于把拦截废掉。
    """

    def test_scoped_exception_skipped(self):
        rs = RuleSet()
        rs.add_line("||ads.tracker.com^")
        rs.add_line("||cloudflare.com^")
        rs.add_line("@@||cloudflare.com/cdn-cgi/trace$domain=site.com", strict=True)
        self.assertTrue(rs.is_blocked("ads.tracker.com"))
        # 作用域例外被丢弃 → cloudflare.com 仍然按屏蔽规则处理
        self.assertTrue(rs.is_blocked("cdn.cloudflare.com"))
        self.assertEqual(rs.skipped, 1)

    def test_scoped_block_skipped(self):
        rs = RuleSet()
        rs.add_line("||cdn.shared.com^$domain=bad.com", strict=True)
        self.assertFalse(rs.is_blocked("cdn.shared.com"))
        self.assertEqual(rs.count, 0)

    def test_path_rule_skipped_in_strict(self):
        rs = RuleSet()
        rs.add_line("||example.com/api/ad/*^", strict=True)
        rs.add_line("|https://banner.example.com/x.js", strict=True)
        self.assertEqual(rs.count, 0)
        self.assertEqual(rs.skipped, 2)

    def test_plain_and_modifier_kept(self):
        rs = RuleSet()
        rs.add_line("||ads.com^$third-party", strict=True)
        rs.add_line("0.0.0.0 x.test", strict=True)
        self.assertTrue(rs.is_blocked("ads.com"))
        self.assertTrue(rs.is_blocked("x.test"))
        self.assertEqual(rs.skipped, 0)

    def test_non_strict_keeps_legacy_behaviour(self):
        rs = RuleSet()
        rs.add_line("|https://banner.example.com/path?x=1")
        self.assertTrue(rs.is_blocked("banner.example.com"))
        rs2 = RuleSet()
        rs2.add_line("@@||cdn.example.com/x$domain=a.com")
        self.assertFalse(rs2.is_blocked("cdn.example.com"))

    def test_compile_rules_strict(self):
        rs = compile_rules(["||a.com^", "||b.com/path^"], strict=True)
        self.assertTrue(rs.is_blocked("a.com"))
        self.assertFalse(rs.is_blocked("b.com"))
        self.assertEqual(rs.count, 1)


class TestStateReuse(unittest.TestCase):
    """编译结果复用：absorb 出来的集合必须和重新解析完全一致。"""

    def test_absorb_matches_recompile(self):
        lines = ["||ads.com^", "@@||ok.ads.com^", "0.0.0.0 t.test", "/^ad[0-9]+\\.x\\.com$/"]
        src = compile_rules(lines, strict=True)
        dst = RuleSet().absorb(src.state())
        self.assertEqual(dst.count, src.count)
        for d in ("ads.com", "x.ads.com", "ok.ads.com", "t.test", "ad1.x.com", "www.qq.com"):
            self.assertEqual(dst.match(d), src.match(d), d)

    def test_absorb_two_states(self):
        a = compile_rules(["||a.com^"]).state()
        b = compile_rules(["@@||ok.a.com^", "||b.com^"]).state()
        dst = RuleSet().absorb(a).absorb(b)
        self.assertTrue(dst.is_blocked("a.com"))
        self.assertFalse(dst.is_blocked("ok.a.com"))
        self.assertTrue(dst.is_blocked("b.com"))
        self.assertEqual(dst.count, 3)

    def test_state_is_readonly(self):
        st = compile_rules(["||a.com^"]).state()
        self.assertIsInstance(st["suffix"], frozenset)
