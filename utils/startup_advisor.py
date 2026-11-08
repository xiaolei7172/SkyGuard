#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
开机启动项建议引擎

目标：不只是列出启动项，还要告诉用户「哪些该关、为什么、关了会怎样」。
三类结论：
  disable  建议关闭——冗余自启，关掉不影响软件正常使用
  keep     建议保留——安全防护 / 输入法 / 系统托盘等必需组件
  optional 可选——聊天、网盘、开发工具等，取决于个人用法

判定顺序（顺序即优先级，避免互相误伤）：
  1. 命令指向的文件已不存在 → 直接建议关闭（无效残留）
  2. 安全软件、输入法、系统托盘 → 保留
  3. 硬件驱动 / 厂商工具 → 可选（保留更稳妥）
  4. 自动更新程序 → 关闭
  5. 游戏平台、影音、推广捆绑 → 关闭
  6. 聊天办公、云同步、下载网盘、开发工具 → 可选
  7. 未识别 → 可选（保守，不乱劝人关）

只做建议，不做任何修改；启停仍由 startup_manager 的可逆机制执行。
"""

import os
import re

VERDICT_DISABLE = "disable"
VERDICT_KEEP = "keep"
VERDICT_OPTIONAL = "optional"

VERDICT_LABELS = {
    VERDICT_DISABLE: "建议关闭",
    VERDICT_KEEP: "建议保留",
    VERDICT_OPTIONAL: "可选",
}

# 类别 → (典型启动耗时毫秒, 是否需要管理员关注)
CATEGORY_COST = {
    "安全防护": 1200,
    "输入法": 400,
    "系统托盘": 350,
    "硬件驱动": 900,
    "自动更新": 900,
    "游戏平台": 2600,
    "影音娱乐": 1600,
    "下载网盘": 2100,
    "聊天办公": 2200,
    "云同步": 1800,
    "开发工具": 2600,
    "推广捆绑": 1100,
    "无效残留": 300,
    "未知": 800,
}

# (类别, 正则, 结论, 理由, 关闭影响, 匹配范围)
# 匹配范围：name=只匹配名称（防止安装路径碰巧含关键词而误伤）；both=名称+命令
# 正则匹配对象统一转小写
_RULES = [
    # ---------- 必须保留：安全防护 ----------
    ("安全防护",
     r"(windows defender|securityhealth|msmpeng|360safe|360tray|360sd|360安全|360.*卫士|"
     r"huorong|火绒|"
     r"kaspersky|卡巴|mcafee|norton|诺顿|eset|avast|avg antivirus|bitdefender|"
     r"qqpcmgr|腾讯电脑管家|金山毒霸|kingsoft|瑞星|rising)",
     VERDICT_KEEP,
     "安全软件需要开机常驻才能提供实时防护与拦截",
     "关闭后实时防护会延后生效，存在安全风险，不建议关闭",
     "both"),

    # ---------- 必须保留：输入法 / 系统托盘 ----------
    ("输入法",
     r"(ctfmon|sogou.*(ime|input|pinyin)|搜狗拼音|qqpinyin|qq拼音|baidu.*pinyin|"
     r"百度输入法|微软拼音|inputmethod|ime\\w*\.exe)",
     VERDICT_KEEP,
     "输入法与系统托盘是日常打字、切换语言的必需组件",
     "关闭后可能无法正常输入中文或切换输入法",
     "both"),

    ("系统托盘",
     r"(systray|系统托盘|realtimesig|audio.*tray|volume)",
     VERDICT_KEEP,
     "系统托盘组件负责音量、网络等状态图标",
     "关闭后相关图标与快捷操作会消失",
     "both"),

    # ---------- 硬件驱动 / 厂商工具 ----------
    ("硬件驱动",
     r"(realtek|synaptics|syntp|elan|alps|touchpad|触控板|dolby|waves|nahimic|"
     r"idt audio|cirrus|fingerprint|指纹|thunderbolt|intel.*(graphics|display)|"
     r"nvidia.*(container|display|experience)|amd.*(radeon|display)|igfx|"
     r"(hotkey|快捷键|atkpackage|armoury|omen|predator)|"
     r"lenovo.*(vantage|utility)|dell.*(support|power|command)|hp.*(support|assistant))",
     VERDICT_OPTIONAL,
     "属于硬件驱动或厂商工具，不关也能用，关了可能失去快捷键/音效增强",
     "如需厂商工具的热键、音效或性能面板，建议保留",
     "both"),

    # ---------- 自动更新（冗余） ----------
    ("自动更新",
     r"(update|updater|更新|升级|upgrade|auto-?update|jusched|msedgeupdate|googleupdate)",
     VERDICT_DISABLE,
     "只是自动检查新版本的常驻程序，手动打开软件时同样能更新",
     "不影响正常使用，只是不再后台自动检查新版本",
     "name"),

    # ---------- 游戏平台 ----------
    ("游戏平台",
     r"(steam|epicgames|epic games|wegame|battle\.net|blizzard|ubisoft|uplay|"
     r"origin|ea app|ea desktop|gog galaxy|雷神加速|网易uu|uu加速|xunyou|迅游|"
     r"游戏加加|gamepp)",
     VERDICT_DISABLE,
     "游戏平台只在玩游戏时才需要，自启纯属占内存",
     "玩游戏时手动打开平台即可，不影响游戏与库存",
     "name"),

    # ---------- 影音娱乐 ----------
    ("影音娱乐",
     r"(iqiyi|爱奇艺|youku|优酷|tencentvideo|腾讯视频|bilibili|哔哩哔哩|"
     r"cloudmusic|网易云音乐|kugou|酷狗|kuwo|酷我|qqmusic|qq音乐|"
     r"potplayer|storm|暴风|realplayer|quicktime|itunes|spotify|"
     r"qqlive|pptv|搜狐视频)",
     VERDICT_DISABLE,
     "影音客户端自启只为了弹推送、抢首页，看的时候再打开即可",
     "不影响播放，只是不再开机弹窗或预加载",
     "name"),

    # ---------- 推广 / 捆绑 / 残留 ----------
    ("推广捆绑",
     r"(adobe.*gc|creative cloud|acrotray|acrobat|office.*(upload|上载)|"
     r"adobearm|apphelper|productupdate|driver.*(genius|精灵|人生)|驱动人生|"
     r"驱动精灵|鲁大师|ludashi|2345|hao123|百度卫士|browser assistant|上网助手|"
     r"wpscloudsvr|kingsoft.*update|sogou.*update|push|daemon.*update)",
     VERDICT_DISABLE,
     "属于更新器、推广组件或捆绑助手，自启后常驻后台且无明显用途",
     "关闭后软件主体功能不受影响，只是少了后台推送与自动升级",
     "both"),

    # ---------- 下载 / 网盘 ----------
    ("下载网盘",
     r"(thunder|迅雷|xunlei|baidunetdisk|百度网盘|quark|夸克|aliyundrive|阿里云盘|"
     r"115|ctdisk|motrix|internet download manager|idm|"
     r"weiyun|微云)",
     VERDICT_OPTIONAL,
     "下载/网盘工具是否需要常驻取决于你是否用它做后台下载或同步",
     "关闭后需手动打开才能继续下载或同步",
     "name"),

    # ---------- 聊天办公 ----------
    ("聊天办公",
     r"(wechat|weixin|微信|qq\.exe|\\tim\\|tim\.exe|dingtalk|钉钉|feishu|lark|飞书|"
     r"wxwork|企业微信|teams|skype|zoom|telegram|discord|slack|钉钉会议)",
     VERDICT_OPTIONAL,
     "聊天办公软件自启是为了及时收消息，工作机常开更省事",
     "关闭后开机不会自动上线，可能漏掉开机时段的消息提醒",
     "name"),

    # ---------- 云同步 ----------
    ("云同步",
     r"(onedrive|dropbox|google ?drive|坚果云|nutstore|seafile|nextcloud|"
     r"syncthing|百度同步|icloud)",
     VERDICT_OPTIONAL,
     "云同步需要常驻才能实时同步文件",
     "关闭后本地文件仍可正常使用，但不会自动上传/拉取",
     "name"),

    # ---------- 开发 / 虚拟机 ----------
    ("开发工具",
     r"(docker|wsl|vmware|virtualbox|jetbrains|pycharm|idea64|webstorm|"
     r"xampp|wamp|mysql|postgres|redis|mongodb|navicat|git bash|"
     r"github desktop|sourcetree|postman|figma|unity|unreal)",
     VERDICT_OPTIONAL,
     "开发/虚拟化工具自启会明显拖慢开机，用时再启动更合适",
     "关闭后需要手动启动对应服务或 IDE",
     "name"),
]

# 常见系统组件（启动项里的官方项，建议保留）
_SYSTEM_KEEP = re.compile(
    r"(securityhealth|windows.*security|microsoft.*(onedrive|teams)|"
    r"startmenuexperience|shellapp|explorer\.exe|ctfmon)",
    re.IGNORECASE,
)


class Advice:
    """一条启动项建议"""

    __slots__ = ("verdict", "category", "reason", "impact", "est_ms", "score")

    def __init__(self, verdict, category, reason, impact, est_ms, score):
        self.verdict = verdict
        self.category = category
        self.reason = reason
        self.impact = impact
        self.est_ms = est_ms
        self.score = score

    @property
    def label(self):
        return VERDICT_LABELS.get(self.verdict, "可选")

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "label": self.label,
            "category": self.category,
            "reason": self.reason,
            "impact": self.impact,
            "est_ms": self.est_ms,
            "score": self.score,
        }


def extract_program(command):
    """从启动命令里取出可执行文件路径（解析失败返回空串）"""
    if not command:
        return ""
    cmd = os.path.expandvars(command).strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 1 else ""
    low = cmd.lower()
    # 系统宿主进程不判失效
    if low.startswith(("rundll32", "cmd", "powershell", "wscript", "cscript", "mshta", "explorer")):
        return ""
    exe_pos = low.find(".exe")
    if exe_pos > 0:
        return cmd[:exe_pos + 4].strip()
    if os.path.isfile(cmd):
        return cmd
    return cmd.split(" ")[0] if cmd else ""


def program_missing(command):
    """命令指向的程序是否已不存在（仅对明确的 exe 路径判定）"""
    prog = extract_program(command)
    if not prog or not prog.lower().endswith((".exe", ".bat", ".cmd", ".lnk")):
        return False
    if not os.path.isabs(prog):
        return False
    return not os.path.exists(prog)


def _cost_score(est_ms):
    return max(5, min(100, int(est_ms / 30)))


def advise(item):
    """对单个启动项给出建议 → Advice"""
    name = (getattr(item, "name", "") or "")
    command = (getattr(item, "command", "") or "")
    haystack = f"{name} {command}".lower()
    kind = getattr(item, "kind", "")

    # 1) 无效残留优先
    if kind in ("run", "runonce", "folder") and program_missing(command):
        return Advice(VERDICT_DISABLE, "无效残留",
                      "启动命令指向的程序已不存在（软件已卸载或移动），这条启动项已经失效",
                      "关闭不会有任何影响，顺手清理掉还能让启动列表更干净",
                      CATEGORY_COST["无效残留"], _cost_score(CATEGORY_COST["无效残留"]))

    # 1.5) 系统服务只展示，不建议随意动
    if kind == "service":
        if "系统组件" in (getattr(item, "detail", "") or ""):
            return Advice(VERDICT_KEEP, "系统托盘",
                          "Windows 自带服务，系统按需加载",
                          "关闭可能导致系统功能异常，请勿在此调整；如需优化请用「服务」管理器",
                          0, 0)
        return Advice(VERDICT_OPTIONAL, "系统托盘",
                      "第三方服务，是否常驻取决于该软件是否需要后台能力",
                      "关闭后对应软件的后台功能会停用，建议确认用途后再动",
                      600, _cost_score(600))

    # 1.6) Windows 自带计划任务（\Microsoft\ 下）不作为优化对象
    if kind == "task" and (getattr(item, "task_path", "") or "").lower().startswith("\\microsoft\\"):
        return Advice(VERDICT_KEEP, "系统托盘",
                      "Windows 自带计划任务，系统更新与维护依赖它",
                      "关闭可能影响系统更新或维护功能，不建议调整",
                      0, 0)

    # 2) 系统官方组件
    if _SYSTEM_KEEP.search(haystack):
        return Advice(VERDICT_KEEP, "系统托盘",
                      "Windows 官方组件，属于系统正常启动流程",
                      "关闭可能影响系统功能或登录体验",
                      300, _cost_score(300))

    # 3) 规则表（顺序即优先级；scope 决定只匹配名称还是名称+命令）
    for category, pattern, verdict, reason, impact, scope in _RULES:
        target = name if scope == "name" else haystack
        if re.search(pattern, target, re.IGNORECASE):
            est = CATEGORY_COST.get(category, 800)
            # 用户目录下的程序启动通常更慢（磁盘随机读 + 未预读）
            if "%userprofile%" in command.lower() or "appdata" in command.lower():
                est = int(est * 1.15)
            return Advice(verdict, category, reason, impact, est, _cost_score(est))

    # 4) 未识别
    return Advice(VERDICT_OPTIONAL, "未知",
                  "未识别到明确的用途，可能是小众工具或自安装程序",
                  "不确定用途时建议保留观察；若确认已不用，再关闭更稳妥",
                  CATEGORY_COST["未知"], _cost_score(CATEGORY_COST["未知"]))


def advise_all(items):
    """给每个启动项挂上 advice 属性（不改动原对象结构，用 dict 缓存）"""
    result = {}
    for item in items:
        result[item.key] = advise(item)
    return result


def summarize(items, advices):
    """汇总：总数 / 启用数 / 建议关闭数 / 预计可缩短的开机时间"""
    enabled = [i for i in items if i.enabled]
    disable_enabled = [i for i in enabled
                       if advices.get(i.key) and advices[i.key].verdict == VERDICT_DISABLE
                       and getattr(i, "editable", True)]
    saving_ms = sum(advices[i.key].est_ms for i in disable_enabled)
    return {
        "total": len(items),
        "enabled": len(enabled),
        "suggest_disable": len(disable_enabled),
        "suggest_disable_keys": [i.key for i in disable_enabled],
        "est_saving_ms": saving_ms,
    }
