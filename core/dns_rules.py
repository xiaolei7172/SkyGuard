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

strict（DNS 层严格）模式：
  DNS 服务器只拿得到域名，拿不到 URL 路径和「哪个站点发起的请求」。因此：
  - 带 `$domain=` / `$denyallow=` / `$client=` 等作用域修饰符的规则会跳过。
    这类规则去掉修饰符后会退化成「整域放行/整域拦截」，把 qq.com、cloudflare.com
    这种大站整体放行，等于把拦截功能废掉，宁可不用。
  - 带路径的规则（`||host/path`、`|http://host/path`）同样跳过：
    只能取主机名会连正常内容一起拦（或一起放），误伤面太大。
  只有在严格模式下，`count` 才是「真正在 DNS 层生效的条数」。
"""

import re

COMMENT_PREFIXES = ("!", "#", "//", "[")
HOSTS_PREFIXES = ("0.0.0.0", "127.0.0.1", "::1", "::", "255.255.255.255")

# 带这些修饰符的规则必须结合「发起请求的站点」判断，DNS 层无法表达
SCOPE_MODIFIERS = ("domain=", "denyallow=", "client=", "app=", "stealth=",
                   "ctag=", "from=")

# 元素隐藏 / 脚本注入类语法（`example.com##.ad`、`#@#`、`#$#`…）。
# 这类规则只对浏览器版广告插件有意义，DNS 层必须整条丢弃：
# 若按「取主机名」处理，会变成把 example.com 整站拦截。
COSMETIC_MARKERS = ("##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#%#", "#@%#")

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
        self._skipped = 0

    # ---------------- 构建 ----------------
    def add_line(self, line, strict=False):
        """加入一条规则。返回 'block' / 'allow' / None（无效或忽略）。

        strict=True 时按 DNS 层能力裁剪：跳过作用域修饰符与带路径的规则，
        详见模块文档。
        """
        raw = (line or "").strip().lstrip("\ufeff")
        if not raw or raw.startswith(COMMENT_PREFIXES):
            return None
        # 元素隐藏 / 脚本注入规则在 DNS 层无意义，且按域名解析会把整站误拦
        if any(mark in raw for mark in COSMETIC_MARKERS):
            self._skipped += 1
            return None
        # 去掉 AdGuard 修饰符（记录下修饰符，strict 模式要靠它判断作用域）
        modifiers = ""
        if "$" in raw and not raw.startswith("/"):
            raw, modifiers = raw.split("$", 1)
            raw = raw.strip()
            modifiers = modifiers.strip().lower()
        if not raw:
            return None
        if strict and modifiers and any(k in modifiers for k in SCOPE_MODIFIERS):
            # 例：@@||cloudflare.com/cdn-cgi/trace$domain=net.ljxnet.cn
            # 去掉 $domain 会变成「整站放行 cloudflare.com」，必须丢弃
            self._skipped += 1
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
            rest = body[2:].split("^", 1)[0]
            if strict and "/" in rest:
                # ||host/path 只能按路径命中，DNS 层退化成整域会误伤
                self._skipped += 1
                return None
            domain = rest.split("/", 1)[0]
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
            if strict and "/" in body.split("^", 1)[0]:
                self._skipped += 1
                return None
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

    def extend(self, lines, strict=False):
        for line in lines or ():
            self.add_line(line, strict=strict)
        return self._lines

    # ------------- 编译结果复用（避免大列表每次重建都重新解析） -------------
    def state(self):
        """导出一份只读的编译结果快照，可被其他 RuleSet 用 absorb() 直接吸收。

        返回的集合是 frozenset，外部只读，不会污染本对象。
        """
        return {
            "exact": frozenset(self._exact),
            "suffix": frozenset(self._suffix),
            "regex": tuple(self._regex),
            "allow_exact": frozenset(self._allow_exact),
            "allow_suffix": frozenset(self._allow_suffix),
            "allow_regex": tuple(self._allow_regex),
            "lines": self._lines,
            "invalid": self._invalid,
            "skipped": self._skipped,
        }

    def absorb(self, state):
        """吸收另一份编译结果（集合直接拷贝，比重放几十万行文本快一个量级）。"""
        if not state:
            return self
        # 注意：空 frozenset 是假值，不能用 `or ()` 兜底（会是 tuple，|= 直接报错）
        for key, target in (("exact", self._exact), ("suffix", self._suffix),
                            ("allow_exact", self._allow_exact),
                            ("allow_suffix", self._allow_suffix)):
            src = state.get(key)
            if src:
                target |= src
        self._regex.extend(state.get("regex") or ())
        self._allow_regex.extend(state.get("allow_regex") or ())
        self._lines += int(state.get("lines", 0) or 0)
        self._invalid += int(state.get("invalid", 0) or 0)
        self._skipped += int(state.get("skipped", 0) or 0)
        return self

    # ---------------- 查询 ----------------
    @property
    def count(self):
        return self._lines

    @property
    def invalid(self):
        return self._invalid

    @property
    def skipped(self):
        """strict 模式下被跳过的条数（作用域 / 带路径规则）。"""
        return self._skipped

    @property
    def suffix_count(self):
        return len(self._suffix)

    @property
    def allow_count(self):
        return len(self._allow_suffix) + len(self._allow_regex)

    def block_domains(self, limit=20000):
        """导出可给内核 rule-provider（behavior: domain）用的拦截域名。

        - 后缀规则转成 mihomo 的 '+.example.com'（含子域）
        - 完整域名原样
        - 例外（@@）与正则不导出：内核侧无法表达，硬塞会误伤
        """
        out = []
        for suffix in sorted(self._suffix):
            if suffix in self._allow_suffix:
                continue
            out.append("+." + suffix)
        for exact in sorted(self._exact):
            if exact in self._allow_exact:
                continue
            out.append(exact)
        return out[:limit]

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


def compile_rules(*rule_groups, strict=False):
    """把多组规则（列表可迭代对象或字符串）编译成一个 RuleSet。

    strict=True 按 DNS 层能力裁剪（跳过作用域修饰符与带路径规则）。
    """
    ruleset = RuleSet()
    for group in rule_groups:
        if isinstance(group, str):
            ruleset.extend(parse_filter_list(group), strict=strict)
        elif group:
            ruleset.extend(group, strict=strict)
    return ruleset
