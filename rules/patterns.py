"""注入攻击的正则模式表。

每条含名称、正则、风险权重、说明四块。权重越高，命中后越倾向于
判成注入攻击；不同攻击手法给不同权重，方便和关键词、越狱句一起加权。
"""
import re

INJECTION_PATTERNS = [
    # ---- 系统身份伪造 ----
    {"name": "系统身份标记", "pattern": r"\[\s*(system|admin|developer|assistant)\s*\]\s*[:：]", "weight": 5, "desc": "伪造系统或管理员发言标记"},
    {"name": "系统消息注入", "pattern": r"\{\s*\"role\"\s*:\s*\"system\"", "weight": 5, "desc": "结构化消息伪造系统角色"},
    {"name": "特殊系统标签", "pattern": r"<<\s*SYS\s*>>|<\s*\/?\s*SYS\s*>", "weight": 5, "desc": "SYS 标签包裹伪系统指令"},
    {"name": "开发指令标签", "pattern": r"<\s*(system|developer|instruction|prompt)\s*>", "weight": 4, "desc": "尖括号伪指令标签"},
    {"name": "伪造系统命令", "pattern": r"\[(system|admin)\s*(internal|command)\]\s*:", "weight": 5, "desc": "伪造系统内部命令标记"},
    {"name": "SYSTEM指令", "pattern": r"^/system\s+.+", "weight": 4, "desc": "斜杠 system 伪指令"},
    {"name": "JSON系统消息伪造", "pattern": r"\"messages\"\s*:\s*\[\s*\{[^}]*\"role\"\s*:\s*\"system\"", "weight": 5, "desc": "伪造 messages 数组中的系统角色"},
    {"name": "伪造日志标签", "pattern": r"\[\d{2}:\d{2}:\d{2}\].*?\[\d{5,12}\].*", "weight": 4, "desc": "伪造带时间戳与ID的日志标签"},
    # ---- 忽略/覆盖既有指令 ----
    {"name": "忽略既有指令", "pattern": r"(忽略|无视|抛弃|放弃).{0,6}(以上|之前|此前|所有|先前).{0,6}(指令|规则|要求|设定|提示词)", "weight": 5, "desc": "要求忽略已存在的指令"},
    {"name": "遗忘设定诱导", "pattern": r"(忘记|忘掉|遗忘|forget).{0,8}(你的|系统|自身|当前|之前|所有).{0,8}(提示词|设定|规则|指令|人设|身份|约束|system\s*prompt)", "weight": 5, "desc": "要求遗忘系统设定或规则"},
    {"name": "覆盖规则诱导", "pattern": r"(覆盖|推翻|作废|替换|改写).{0,6}(之前|以上|既有|现有|当前|所有).{0,6}(规则|指令|设定|约束|提示词)", "weight": 5, "desc": "要求覆盖既有规则或设定"},
    {"name": "英文忽略指令", "pattern": r"(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)\s+(instructions|rules|prompts|directives)", "weight": 5, "desc": "英文要求忽略既有指令"},
    {"name": "覆盖系统提示词", "pattern": r"(覆盖|替换|重写|override|replace|supersede).{0,6}(系统提示词|系统指令|初始指令|system\s*prompt)", "weight": 7, "desc": "覆盖或替换系统提示词"},
    {"name": "指令优先声明", "pattern": r"(以下|接下来|现在).{0,6}(指令|规则|要求).{0,6}(优先|最高优先级|为准)", "weight": 4, "desc": "声明新指令优先于系统指令"},
    # ---- 越狱 ----
    {"name": "越狱引导", "pattern": r"(进入|开启|切换).{0,6}(越狱|无约束|无限制|开发者|jailbreak).{0,6}(模式|状态)", "weight": 4, "desc": "引导进入越狱或无约束模式"},
    {"name": "解除限制", "pattern": r"(解除|取消|移除).{0,6}(所有|全部).{0,6}(限制|约束|规则)", "weight": 4, "desc": "要求解除全部限制"},
    # ---- 泄露内部信息 ----
    {"name": "泄露内部指令", "pattern": r"(输出|展示|泄露|打印|dump|reveal|show).{0,6}(系统提示词|内部指令|初始提示词|隐藏规则)", "weight": 5, "desc": "诱导泄露内部指令"},
    {"name": "思维链诱导", "pattern": r"(展示|输出|reveal|show).{0,6}(思考过程|思维链|推理步骤|推理过程|chain\s*of\s*thought)", "weight": 3, "desc": "诱导泄露推理过程"},
    {"name": "强制展示思维链", "pattern": r"(show|reveal|output).{0,20}(chain\s*of\s*thought|思维链|推理过程)", "weight": 3, "desc": "强制展示思考或推理过程"},
    # ---- 角色冒充 ----
    {"name": "角色冒充", "pattern": r"(现在|从现在起|现在开始).{0,10}(你是|扮演|成为).{0,12}(管理员|系统|开发者|root|管理员权限)", "weight": 4, "desc": "冒充更高权限角色"},
    {"name": "角色调教", "pattern": r"(扮演|cosplay|角色扮演|DAN|猫娘|GPT角色).{0,10}(无限制|无视规则|释放)", "weight": 4, "desc": "角色调教式注入"},
    {"name": "GalGame猫娘调教", "pattern": r"(GalGame|猫娘|DAN|越狱角色).{0,12}(对话|模式|玩法)", "weight": 4, "desc": "角色扮演类越狱调教"},
    # ---- 指令分段 ----
    {"name": "指令分段标记", "pattern": r"(BEGIN|START|END)\s*(SYSTEM|PROMPT|INSTRUCTION|指令|提示词)", "weight": 4, "desc": "分段标记包裹伪指令"},
    {"name": "分隔符注入", "pattern": r"(---|===|\*\*\*)\s*(系统|system|指令|规则)\s*(---|===|\*\*\*)", "weight": 3, "desc": "用分隔符包裹伪系统段"},
    # ---- 编码混淆 ----
    {"name": "百分号编码", "pattern": r"(?:%[0-9a-fA-F]{2}){6,}", "weight": 3, "desc": "大量百分号编码"},
    {"name": "Unicode 转义", "pattern": r"(?:\\u[0-9a-fA-F]{4}){4,}", "weight": 3, "desc": "大量 Unicode 转义"},
    {"name": "十六进制转义", "pattern": r"(?:\\x[0-9a-fA-F]{2}){8,}", "weight": 3, "desc": "大量十六进制转义"},
    {"name": "Base64 片段", "pattern": r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])", "weight": 3, "desc": "疑似 base64 编码片段"},
    {"name": "DataURI注入", "pattern": r"data:[^;]+;base64,[A-Za-z0-9+/]{24,}={0,2}", "weight": 4, "desc": "data URI 内嵌 base64 负载"},
    # ---- 脚本/代码注入 ----
    {"name": "脚本执行注入", "pattern": r"(powershell|cmd\s*/c|bash\s*-c|curl|wget|Invoke-WebRequest|iwr)\s+.{0,60}(https?://|-enc\s)", "weight": 4, "desc": "引导执行外部脚本"},
    {"name": "工具调用伪造", "pattern": r"\"(function_call|tool_use|tool_calls)\"\s*:\s*\{", "weight": 4, "desc": "伪造工具调用"},
    {"name": "代码块注入", "pattern": r"```(python|json|shell|bash|system)", "weight": 3, "desc": "代码块包裹伪指令"},
    {"name": "PowerShell编码执行", "pattern": r"powershell(?:\.exe)?\s+-enc\s+[A-Za-z0-9+/=]{20,}", "weight": 4, "desc": "PowerShell -enc 编码执行"},
    {"name": "Certutil解码", "pattern": r"certutil\s+-decode\s+\S+", "weight": 4, "desc": "certutil 解码外部内容"},
    {"name": "Bitsadmin传输", "pattern": r"bitsadmin\s+/transfer\b", "weight": 4, "desc": "bitsadmin 传输外部负载"},
    {"name": "HTML注释注入", "pattern": r"<!--\s*(system prompt|override)", "weight": 4, "desc": "HTML 注释包裹伪指令"},
    # ---- 高危/违规任务 ----
    {"name": "高危任务诱导", "pattern": r"(制作|编写|输出).{0,20}(炸弹|病毒|漏洞|非法|攻击|黑客)", "weight": 4, "desc": "诱导生成高危或违规内容"},
    # ---- 唆使 AI 执行危险操作（修改服务器/删文件/跑命令）----
    {"name": "危险操作诱导", "pattern": r"(修改|更改|删除|清空|关闭|重启|停止).{0,8}(服务器|配置文件|数据库|系统文件|用户数据|服务|密码)", "weight": 7, "desc": "唆使修改或破坏服务器内容"},
    {"name": "破坏性命令", "pattern": r"(rm\s+-rf|rm\s+-fr|mkfs|shutdown|reboot|drop\s+table|truncate\s+table|kill\s+-9|chmod\s+777|dd\s+if=)", "weight": 6, "desc": "破坏性 shell 命令"},
    {"name": "命令执行诱导", "pattern": r"(执行|运行|帮我跑|跑一下|跑这段).{0,8}(命令|脚本|shell|代码|这段)", "weight": 4, "desc": "诱导执行任意命令或代码"},
    {"name": "提示词泄露变体", "pattern": r"(把|将).{0,8}(你的|系统的|初始).{0,8}(提示词|指令|设定|prompt).{0,8}(发给|告诉|给我|贴出|复制)", "weight": 5, "desc": "诱导贴出系统提示词的变体表述"},

    # ---- 绕过安全策略 ----
    {"name": "拒绝服务误导", "pattern": r"(忽略|无视).{0,10}(安全|内容政策|审核|规则限制|safety|policy)", "weight": 4, "desc": "绕过安全或内容政策"},
    {"name": "虚构成分诱导", "pattern": r"(假装|想象|假设|pretend|imagine|hypothetical).{0,20}(没有|无|不存在).{0,10}(限制|规则|安全)", "weight": 4, "desc": "虚构场景绕过限制"},
]

# 供检测时预编译使用的编译后模式列表
COMPILED_PATTERNS = [
    {"name": p["name"], "regex": re.compile(p["pattern"], re.IGNORECASE), "weight": p["weight"]}
    for p in INJECTION_PATTERNS
]
