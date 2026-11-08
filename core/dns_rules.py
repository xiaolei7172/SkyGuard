#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""AdGuard Home 风格的过滤规则引擎（实用子集）。

支持的写法（一行一条，互相可混用）：

    # 注释 / ! 注释
    example.com                 屏蔽该域及其全部子域（hosts 习惯）
    *.example.com               同上
    0.0.0.0 example.com         标准 hosts 行（也认 127.0.0.1 / :: / ::1）
    ||example.com^              AdGuard 域名锚定，屏蔽该域及其子域
    @@||example.com^            例外（放行），优先级高于屏蔽
    @@example.com               例外（hosts 风格）
    |http://example.com/path    URL 规则，取其中的主机名
    /^ads?[0-9]*\\./            正则规则（前后带 /）
    @@/^ok[0-9]*\\./            正则例外

说明：
  - `$` 后面的修饰符（如 $third-party）暂不支持，解析时直接忽略；
  - 例外规则永远优先于屏蔽规则，与 AdGuard 行为一致；
  - 全部规则编译成 exact / suffix / regex 三组索引，查询是 O(域名标签数)。
"""

import re

COMMENT_PREFIXES = ("!", "#", "//", "[")
HOSTS_PREFIXES = ("0.0.0.0", "127.0.0.1", "::1", "::", "255.255.255.255")

MAX_REGEX_LEN = 400


def normalize_domain(text):
    """域名归一化：去空白、小写、去末尾点、去通配前缀。无效返回空串。"""
    text = (text or "").strip().lower().rstrip(".")
    if not text:
        return ""
    if text.startswith("*."):
        text = text[2:]
    if text.startswith("."):
        text = text[1:]
    if not text or " " in text:
        return ""
    # 只接受域名形态：字母数字、连字符、点、下划线、国际化域名
    if not re.fullmatch(r"[a-z0-9_\-\.\u00a1-\uffff]+", text):
        return ""
    if "." not in text and ":" not in text:
        return ""
    return text


class RuleSet:
    """一组过滤规则的编译结果，线程内只读匹配，可随时整体替换。"""

    def __init__(self):
        self._exact = set()
        self._suffix = set()
        self._regex = []
        self._allow_exact = set()
        self._allow_suffix = set()
        self._allow_regex = []
        self._lines = 0
        self._invalid = 0

    # ---------------- 构建 ----------------
    def add_line(self, line):
        """加入一条规则。返回 'block' / 'allow' / None（无效或忽略）。"""
        raw = (line or "").strip().lstrip("\ufeff")
        if not raw or raw.startswith(COMMENT_PREFIXES):
            return None
        # 去掉 AdGuard 修饰符
        if "$" in raw and not raw.startswith("/"):
            raw = raw.split("$", 1)[0].strip()
        if not raw:
            return None

        allow = raw.startswith("@@")
        if allow:
            raw = raw[2:].strip()
            if not raw:
                return None

        body = raw
        kind = None

        # 正则规则：/.../
        if body.startswith("/") and body.endswith("/") and len(body) > 2:
            pattern = body[1:-1]
            if len(pattern) <= MAX_REGEX_LEN:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    self._invalid += 1
                    return None
                (self._allow_regex if allow else self._regex).append(
                    (compiled, f"{'@@' if allow else ''}/{pattern}/"))
                self._lines += 1
                return "allow" if allow else "block"
            self._invalid += 1
            return None

        # hosts 行：0.0.0.0 domain [domain2 ...]
        parts = body.split()
        if len(parts) >= 2 and parts[0] in HOSTS_PREFIXES:
            added = None
            for cand in parts[1:]:
                cand = cand.split("#", 1)[0]
                domain = normalize_domain(cand)
                if not domain:
                    continue
                if allow:
                    self._allow_exact.add(domain)
                    self._allow_suffix.add(domain)
                    added = "allow"
                else:
                    self._exact.add(domain)
                    self._suffix.add(domain)
                    added = "block"
            if added:
                self._lines += 1
            return added

        # ABP 域名锚定：||domain^
        if body.startswith("||"):
            domain = body[2:].split("^", 1)[0].split("/", 1)[0]
            domain = normalize_domain(domain)
            if not domain:
                self._invalid += 1
                return None
            if allow:
                self._allow_suffix.add(domain)
            else:
                self._suffix.add(domain)
            self._lines += 1
            return "allow" if allow else "block"

        # URL 规则：|http://host/path
        if body.startswith("|"):
            body = body.lstrip("|")
            if "://" in body:
                body = body.split("://", 1)[1]
            host = body.split("/", 1)[0].split("^", 1)[0]
            domain = normalize_domain(host)
            if not domain:
                self._invalid += 1
                return None
            if allow:
                self._allow_suffix.add(domain)
            else:
                self._suffix.add(domain)
            self._lines += 1
            return "allow" if allow else "block"

        # 纯域名 / *.domain / domain^
        host = body.split("^", 1)[0].split("/", 1)[0].split("#", 1)[0].strip()
        domain = normalize_domain(host)
        if not domain:
            self._invalid += 1
            return None
        if allow:
            self._allow_exact.add(domain)
            self._allow_suffix.add(domain)
        else:
            self._exact.add(domain)
            self._suffix.add(domain)
        self._lines += 1
        return "allow" if allow else "block"

    def extend(self, lines):
        for line in lines or ():
            self.add_line(line)
        return self._lines

    # ---------------- 查询 ----------------
    @property
    def count(self):
        return self._lines

    @property
    def invalid(self):
        return self._invalid

    @property
    def suffix_count(self):
        return len(self._suffix)

    @property
    def allow_count(self):
        return len(self._allow_suffix) + len(self._allow_regex)

    def _hit_suffix(self, domain, suffix_set):
        if domain in suffix_set:
            return domain
        idx = domain.find(".")
        while idx != -1:
            parent = domain[idx + 1:]
            if parent in suffix_set:
                return parent
            idx = domain.find(".", idx + 1)
        return None

    def match(self, domain):
        """返回 (是否拦截, 命中规则文本)。例外规则优先。"""
        domain = (domain or "").strip().lower().rstrip(".")
        if not domain:
            return False, ""

        # 1) 例外放行
        if domain in self._allow_exact:
            return False, f"@@{domain}"
        hit = self._hit_suffix(domain, self._allow_suffix)
        if hit:
            return False, f"@@||{hit}^"
        for regex, text in self._allow_regex:
            if regex.search(domain):
                return False, text

        # 2) 屏蔽
        if domain in self._exact:
            return True, domain
        hit = self._hit_suffix(domain, self._suffix)
        if hit:
            return True, f"||{hit}^"
        for regex, text in self._regex:
            if regex.search(domain):
                return True, text
        return False, ""

    def is_blocked(self, domain):
        return self.match(domain)[0]


def parse_filter_list(text):
    """把一份过滤列表文本拆成行（自动识别 hosts / ABP / 纯域名）。

    返回规则字符串列表，已去注释与空行，保留原始顺序。
    """
    rules = []
    for line in (text or "").splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith(COMMENT_PREFIXES):
            continue
        rules.append(line)
    return rules


def compile_rules(*rule_groups):
    """把多组规则（列表可迭代对象或字符串）编译成一个 RuleSet。"""
    ruleset = RuleSet()
    for group in rule_groups:
        if isinstance(group, str):
            ruleset.extend(parse_filter_list(group))
        elif group:
            ruleset.extend(group)
    return ruleset
