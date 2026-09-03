"""环境感知：往请求提示词里补时间和平台等上下文。

模型本身不知道「现在几点」「今天星期几」「这是群聊还是私聊」，
这个阶段在每次请求时把这些算出来，拼成一段前缀插到提示词最前面。
能力包括：日期、星期、时间段、节气、干支生肖、节假日、
平台、群名、消息类型（是否含图片/语音/视频）。
"""
from datetime import datetime, date

from ..core.stage import Stage

# 农历与节假日库是可选依赖：装了才走完整逻辑，没装自动降级成简化版
try:
    from lunarcalendar import Converter, Solar
    _LUNAR_OK = True
except ImportError:
    _LUNAR_OK = False

try:
    import chinese_calendar as _holiday_lib
    _HOLIDAY_OK = True
except ImportError:
    _HOLIDAY_OK = False

# 农历月名与日名，只在中文字面层做映射，和库无耦合
_LUNAR_MONTH_CN = ["正月", "二月", "三月", "四月", "五月", "六月",
                   "七月", "八月", "九月", "十月", "冬月", "腊月"]
_LUNAR_DAY_CN = ["初一", "初二", "初三", "初四", "初五", "初六", "初七", "初八", "初九", "初十",
                 "十一", "十二", "十三", "十四", "十五", "十六", "十七", "十八", "十九", "二十",
                 "廿一", "廿二", "廿三", "廿四", "廿五", "廿六", "廿七", "廿八", "廿九", "三十"]


# 二十四节气的近似阳历日期（月, 日）
SOLAR_TERMS = [
    ("小寒", 1, 5), ("大寒", 1, 20),
    ("立春", 2, 4), ("雨水", 2, 19),
    ("惊蛰", 3, 5), ("春分", 3, 20),
    ("清明", 4, 5), ("谷雨", 4, 20),
    ("立夏", 5, 5), ("小满", 5, 21),
    ("芒种", 6, 6), ("夏至", 6, 21),
    ("小暑", 7, 7), ("大暑", 7, 23),
    ("立秋", 8, 7), ("处暑", 8, 23),
    ("白露", 9, 7), ("秋分", 9, 23),
    ("寒露", 10, 8), ("霜降", 10, 23),
    ("立冬", 11, 7), ("小雪", 11, 22),
    ("大雪", 12, 7), ("冬至", 12, 22),
]

# 时间段映射
TIME_PERIODS = [
    (5, "凌晨"), (8, "早晨"), (11, "上午"),
    (13, "中午"), (18, "下午"), (22, "晚间"),
    (24, "深夜"),
]

# 平台显示名映射
PLATFORM_NAMES = {
    "aiocqhttp": "QQ",
    "qq": "QQ",
    "wechat": "微信",
    "telegram": "Telegram",
    "wecom": "企业微信",
    "feishu": "飞书",
    "dingtalk": "钉钉",
    "discord": "Discord",
}

# 天干地支与生肖
TIAN_GAN = ["甲", "乙", "丙", "丁", "戊", "己", "庚", "辛", "壬", "癸"]
DI_ZHI = ["子", "丑", "寅", "卯", "辰", "巳", "午", "未", "申", "酉", "戌", "亥"]
SHENG_XIAO = ["鼠", "牛", "虎", "兔", "龙", "蛇", "马", "羊", "猴", "鸡", "狗", "猪"]

# 主要法定节假日（月, 日, 名称），不含调休（调休需年度数据）
HOLIDAYS = [
    (1, 1, "元旦"),
    (5, 1, "劳动节"),
    (10, 1, "国庆节"),
]

WEEKDAY_NAMES = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]


class PerceptionStage(Stage):
    """算当前环境信息，注入请求提示词。"""

    name = "perception"

    def __init__(self, config: dict = None, context=None):
        super().__init__(config, context)

    async def process(self, ctx) -> None:
        if ctx.req is None:
            return

        parts = []
        now = datetime.now()

        if self.config.get("enable_date"):
            parts.append(f"日期：{now.strftime('%Y-%m-%d')}")
        if self.config.get("enable_weekday"):
            parts.append(f"星期：{WEEKDAY_NAMES[now.weekday()]}")
        if self.config.get("enable_time_period"):
            parts.append(f"时间段：{self._time_period(now.hour)}")
        if self.config.get("enable_solar_term"):
            term = self._solar_term(now.month, now.day)
            if term:
                parts.append(f"节气：{term}")
        if self.config.get("enable_lunar"):
            lunar_text = self._lunar_date(now)
            if lunar_text:
                parts.append(f"农历：{lunar_text}")
        if self.config.get("enable_holiday"):
            holiday = self._holiday(now)
            if holiday:
                parts.append(f"节假日：{holiday}")
        if self.config.get("enable_platform"):
            plat = await self._platform(ctx)
            if plat:
                parts.append(f"平台：{plat}")

        if not parts:
            return

        perception = "[环境感知] " + "；".join(parts)
        if hasattr(ctx.req, "prompt"):
            ctx.req.prompt = f"{perception}\n{ctx.req.prompt}"

    # ---------- 内部工具 ----------

    @staticmethod
    def _time_period(hour: int) -> str:
        for upper, name in TIME_PERIODS:
            if hour < upper:
                return name
        return "深夜"

    @staticmethod
    def _solar_term(month: int, day: int) -> str:
        """判断当前日期附近的节气（前后 2 天内）。"""
        for i, (name, m, d) in enumerate(SOLAR_TERMS):
            if month == m and abs(day - d) <= 2:
                if day == d:
                    return f"今日{name}"
                if day < d:
                    return f"临近{name}"
                return f"{name}已过"
        # 取当前日期之前最近的节气
        current = (month, day)
        last = "冬至"
        for name, m, d in SOLAR_TERMS:
            if (m, d) <= current:
                last = name
        return last

    @staticmethod
    def _lunar_date(now: datetime) -> str:
        """完整农历：干支年 + 生肖 + 农历月日（含闰月）。库没装时降级为干支+生肖。"""
        gan = TIAN_GAN[(now.year - 4) % 10]
        zhi = DI_ZHI[(now.year - 4) % 12]
        shengxiao = SHENG_XIAO[(now.year - 4) % 12]
        base = f"{gan}{zhi}年（{shengxiao}年）"
        if not _LUNAR_OK:
            return base
        try:
            lunar = Converter.Solar2Lunar(Solar(now.year, now.month, now.day))
            month = _LUNAR_MONTH_CN[lunar.month - 1]
            if getattr(lunar, "isleap", False):
                month = "闰" + month
            day = _LUNAR_DAY_CN[lunar.day - 1]
            return f"{base}{month}{day}"
        except Exception:
            return base

    @staticmethod
    def _holiday(now: datetime) -> str:
        """节假日 + 调休工作日判断。装了库走完整逻辑，没装退回主要节日近似。"""
        if _HOLIDAY_OK:
            try:
                d = date(now.year, now.month, now.day)
                if _holiday_lib.is_holiday(d):
                    detail = _holiday_lib.get_holiday_detail(d)
                    if detail and detail[1]:
                        return f"{detail[1]}（休息）"
                    return "法定节假日"
                if _holiday_lib.is_workday(d):
                    return "调休工作日" if now.weekday() >= 5 else "工作日"
                return "周末"
            except Exception:
                pass
        # 降级：主要公历节日 + 农历节日近似
        for m, d, name in HOLIDAYS:
            if now.month == m and now.day == d:
                return name
        approx = [
            (2, 10, "春节（约）"), (4, 4, "清明（约）"),
            (6, 10, "端午（约）"), (9, 17, "中秋（约）"),
        ]
        for m, d, name in approx:
            if now.month == m and abs(now.day - d) <= 3:
                return name
        # 没库时至少判断工作日/周末
        return "周末" if now.weekday() >= 5 else "工作日"

    async def _platform(self, ctx) -> str:
        """推断平台来源 + 群聊/私聊 + 群名 + 消息类型。"""
        event = ctx.event
        if event is None:
            return ""
        parts = []

        # 平台类型
        try:
            raw = str(getattr(event, "get_platform_name", lambda: "")() or "")
        except Exception:
            raw = ""
        display = PLATFORM_NAMES.get(raw, raw or "")
        if display:
            parts.append(display)

        # 群聊/私聊
        try:
            msg_type = getattr(event, "get_message_type", lambda: None)()
            mt = str(msg_type or "")
            if "GROUP" in mt.upper():
                parts.append("群聊")
                group_name = await self._group_name(event)
                if group_name:
                    parts.append(f"群名：{group_name}")
            elif "FRIEND" in mt.upper() or "PRIVATE" in mt.upper():
                parts.append("私聊")
        except Exception:
            pass

        # 消息类型（图片/语音/视频）
        try:
            message_obj = getattr(event, "message_obj", None)
            segments = getattr(message_obj, "message", None) or []
            seg_types = {getattr(seg, "type", "") for seg in segments}
            if "image" in seg_types:
                parts.append("含图片")
            if "voice" in seg_types or "audio" in seg_types:
                parts.append("含语音")
            if "video" in seg_types:
                parts.append("含视频")
        except Exception:
            pass

        return " ".join(parts)

    async def _group_name(self, event) -> str:
        """尽力获取群名。"""
        try:
            message_obj = getattr(event, "message_obj", None)
            group_obj = getattr(message_obj, "group", None) if message_obj else None
            if group_obj:
                name = getattr(group_obj, "group_name", None)
                if name and str(name).strip() not in ("", "N/A", "None", "NULL"):
                    return str(name).strip()
        except Exception:
            pass
        return ""
