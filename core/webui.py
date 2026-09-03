"""WebUI 管理面板。

用 aiohttp 起一个本地 HTTP 服务，提供拦截统计、日志查看、全分区配置修改、
黑白名单和封禁管理。页面是内嵌的 HTML/CSS/JS，不依赖 CDN，离线可用。
访问时 URL 带 ?key=密码 做简单鉴权，密码在配置里改。

面板按流水线逻辑顺序排列：防护 → 优化 → 身份 → 感知，后接封禁管理与拦截日志。
"""
import json
from datetime import datetime

from aiohttp import web
from astrbot.api import logger


# 配置里需要读写归一化的字段分组，POST 时按类型规范化，避免前端传错类型
_SCALAR_KEYS = (
    "defense_sensitivity", "defense_action", "post_defense_protection",
    "llm_review", "check_mode", "timezone", "warning_template", "notice_template",
)
_BOOL_KEYS = (
    "auto_ban", "enable_optimize", "enable_auto_backup",
    "enable_jailbreak", "enable_injection_keywords", "enable_injection_patterns",
    "enable_persona_conflict", "enable_hate_detection", "enable_harassment_detection",
    "enable_malicious_link", "enable_encoded_detection", "enable_persona_consistency",
    "enable_platform", "enable_date", "enable_weekday", "enable_time_period",
    "enable_solar_term", "enable_lunar", "enable_holiday",
)
_INT_KEYS = ("ban_duration",)
_LIST_KEYS = (
    "blacklist", "whitelist", "input_blacklist_words", "output_blacklist_words",
    "id_map_list",
)

# 前端页面（内嵌单文件，无外部资源）
_INDEX_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aPromptGuardian</title>
<style>
:root{--bg:#0f1117;--panel:#181b23;--border:#262b38;--text:#e6e8ef;--muted:#8a90a0;--accent:#f59e0b;--danger:#ef4444;--ok:#22c55e}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;line-height:1.6;padding:24px}
h1{font-size:20px;font-weight:600;margin-bottom:4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px}
.card .num{font-size:28px;font-weight:700;color:var(--accent)}
.card .lbl{font-size:12px;color:var(--muted);margin-top:2px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:20px}
.panel h2{font-size:15px;font-weight:600;margin-bottom:14px;color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:500}
td.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}
.row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px}
.field{flex:1;min-width:200px}
.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px}
select,input[type=text],input[type=password],input[type=number]{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 10px;font-size:13px}
textarea{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 10px;font-size:13px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;resize:vertical;min-height:64px}
.switch{display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;user-select:none}
.switch input{accent-color:var(--accent);width:16px;height:16px}
button{background:var(--accent);color:#111;border:none;border-radius:6px;padding:8px 16px;font-size:13px;font-weight:600;cursor:pointer}
button.ghost{background:transparent;border:1px solid var(--border);color:var(--text)}
button.danger{background:var(--danger);color:#fff}
.savebar{display:flex;align-items:center;gap:16px;margin-bottom:20px}
.msg{font-size:13px;margin-top:8px}
.msg.ok{color:var(--ok)}
.msg.err{color:var(--danger)}
.empty{color:var(--muted);font-size:13px;padding:12px 0}
.login{max-width:360px;margin:80px auto;text-align:center}
.login input{margin:12px 0}
.idmap-row{display:flex;gap:8px;margin-bottom:8px}
.idmap-row input{flex:1}
.idmap-row button{flex:0 0 auto;padding:8px 12px}
.hint{font-size:12px;color:var(--muted);margin:2px 0 10px}
@media(prefers-color-scheme:light){
:root{--bg:#f5f6f8;--panel:#fff;--border:#e2e5eb;--text:#1a1d24;--muted:#6b7280}
}
</style>
</head>
<body>
<div id="login" class="login" style="display:none">
  <h1>aPromptGuardian</h1>
  <p class="sub">输入访问密码</p>
  <input type="password" id="pwd" placeholder="密码">
  <button onclick="login()">进入</button>
  <p class="msg" id="loginMsg"></p>
</div>
<div id="app" style="display:none">
  <h1>aPromptGuardian 控制台</h1>
  <p class="sub">提示词防护与增强 · 实时状态</p>
  <div class="grid" id="statCards"></div>

  <div class="panel">
    <h2>优化</h2>
    <div class="field"><label class="switch"><input type="checkbox" id="cfgOptimize"> 启用提示词优化辅助</label></div>
    <div class="hint">⚠️ 开启后会深覆盖当前人设本体，需重载插件后生效。建议先开「自动备份初始提示词」，结果不理想可用下方「回滚人设」按钮恢复。</div>
    <div class="field"><label class="switch"><input type="checkbox" id="cfgAutoBackup"> 自动备份初始提示词（优化前备份，便于回滚）</label></div>
    <button class="ghost" onclick="rollbackPersonas()">回滚人设到初始提示词</button>
    <p class="msg" id="rollbackMsg"></p>
  </div>

  <div class="panel">
    <h2>防护</h2>
    <div class="row">
      <div class="field"><label>防御力度（灵敏度）</label>
        <select id="cfgSens"><option value="low">低（low）</option><option value="medium">中（medium）</option><option value="high">高（high）</option></select></div>
      <div class="field"><label>防御等级（命中后处置）</label>
        <select id="cfgAction"><option value="observe">观察（observe）</option><option value="mark">标注放行（mark）</option><option value="rewrite">仅去除危险内容（rewrite）</option><option value="block">拦截（block）</option></select></div>
      <div class="field"><label>LLM 复核</label>
        <select id="cfgReview"><option value="always">一直（always）</option><option value="risk">判危险时（risk）</option><option value="never">从不（never）</option></select></div>
      <div class="field"><label>防御后保护机制</label>
        <select id="cfgPostProtect"><option value="none">无（none）</option><option value="reread">重读设定（reread）</option><option value="refresh">强制刷新（refresh）</option></select></div>
    </div>
    <div class="row">
      <div class="field"><label class="switch"><input type="checkbox" id="cfgAutoBan"> 命中注入后自动拉黑</label></div>
      <div class="field"><label>自动拉黑时长（分钟，0=永久）</label>
        <input type="number" id="cfgBanDuration" min="0"></div>
    </div>
    <div class="row">
      <div class="field"><label>白名单（每行一个用户 ID，跳过防护）</label>
        <textarea id="cfgWhitelist"></textarea></div>
      <div class="field"><label>黑名单（每行一个用户 ID，命中即拦截）</label>
        <textarea id="cfgBlacklist"></textarea></div>
    </div>
    <div class="row">
      <div class="field"><label>输入黑名单词（每行一个，命中即拦截）</label>
        <textarea id="cfgInputWords"></textarea></div>
      <div class="field"><label>输出黑名单词（每行一个，命中即拦截）</label>
        <textarea id="cfgOutputWords"></textarea></div>
    </div>
    <div class="hint">检测维度开关（默认全开，可单独关闭某类检测）</div>
    <div class="row">
      <div class="field"><label class="switch"><input type="checkbox" id="cfgJailbreak"> 越狱诱导</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgInjKeywords"> 注入关键词</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgInjPatterns"> 注入正则模式</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgPersonaConflict"> 人设冲突</label></div>
    </div>
    <div class="row">
      <div class="field"><label class="switch"><input type="checkbox" id="cfgHate"> 仇恨内容</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgHarass"> 骚扰/辱骂/霸凌</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgMalLink"> 恶意外链</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgEncoded"> 编码混淆</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgPersonaConsist"> 人设一致性</label></div>
    </div>
  </div>

  <div class="panel">
    <h2>身份</h2>
    <div class="row">
      <div class="field"><label>身份检查方式</label>
        <select id="cfgCheckMode"><option value="exact">完全匹配（exact）</option><option value="contain">包含时（contain）</option></select></div>
    </div>
    <div class="field">
      <label>身份映射表（昵称 → 预期真实 ID）</label>
      <div class="hint">把容易被冒用的昵称和它的真实用户 ID 配对；当有人用列表里的昵称但真实 ID 对不上时，会向模型插入身份提醒。</div>
      <div id="idMapList"></div>
      <button class="ghost" onclick="addIdMapRow()">＋ 添加映射项</button>
    </div>
    <div class="row" style="margin-top:12px">
      <div class="field"><label>完全匹配失败提醒模板</label>
        <textarea id="cfgWarningTemplate" placeholder="留空用默认；占位符 {nickname} {actual_id} {expected_id}"></textarea></div>
      <div class="field"><label>包含匹配失败提醒模板</label>
        <textarea id="cfgNoticeTemplate" placeholder="留空用默认；占位符 {actual_nickname} {nickname} {actual_id} {expected_id}"></textarea></div>
    </div>
  </div>

  <div class="panel">
    <h2>感知</h2>
    <div class="field" style="margin-bottom:10px"><label>感知时区</label>
      <input type="text" id="cfgTimezone" placeholder="Asia/Shanghai"></div>
    <div class="row">
      <div class="field"><label class="switch"><input type="checkbox" id="cfgPlatform"> 平台来源</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgDate"> 日期</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgWeekday"> 星期</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgTimePeriod"> 时间段</label></div>
    </div>
    <div class="row">
      <div class="field"><label class="switch"><input type="checkbox" id="cfgSolarTerm"> 节气</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgLunar"> 农历（干支+生肖）</label></div>
      <div class="field"><label class="switch"><input type="checkbox" id="cfgHoliday"> 节假日</label></div>
    </div>
  </div>

  <div class="savebar">
    <button onclick="saveConfig()">保存全部配置</button>
    <p class="msg" id="cfgMsg"></p>
  </div>

  <div class="panel">
    <h2>封禁管理</h2>
    <div class="row">
      <div class="field"><input type="text" id="banId" placeholder="用户 ID"></div>
      <div class="field"><input type="number" id="banMin" placeholder="分钟（0=永久）" value="60"></div>
      <button class="danger" onclick="doBan()">拉黑</button>
    </div>
    <table id="banTable"><thead><tr><th>用户 ID</th><th>剩余</th><th>操作</th></tr></thead><tbody></tbody></table>
  </div>

  <div class="panel">
    <h2>最近拦截日志</h2>
    <table id="logTable"><thead><tr><th>时间</th><th>用户</th><th>处置</th><th>原因</th></tr></thead><tbody></tbody></table>
  </div>
</div>
<script>
let KEY = new URLSearchParams(location.search).get('key') || localStorage.getItem('pg_key') || '';
function api(path){return fetch(path + (path.includes('?')?'&':'?') + 'key=' + encodeURIComponent(KEY));}
function login(){
  const v = document.getElementById('pwd').value;
  if(!v){document.getElementById('loginMsg').textContent='请输入密码';return;}
  KEY = v; localStorage.setItem('pg_key', v); location.search = '?key=' + v;
}
function showLogin(){document.getElementById('login').style.display='block';}
function showApp(){document.getElementById('app').style.display='block';}
async function boot(){
  const r = await api('/api/stats');
  if(r.status === 401){showLogin();return;}
  showApp(); refresh();
}

// 感知开关 id -> 配置键
const PERCEPTION = [
  ['cfgPlatform','enable_platform'], ['cfgDate','enable_date'], ['cfgWeekday','enable_weekday'],
  ['cfgTimePeriod','enable_time_period'], ['cfgSolarTerm','enable_solar_term'], ['cfgLunar','enable_lunar'],
  ['cfgHoliday','enable_holiday'],
];
const DETECT = [
  ['cfgJailbreak','enable_jailbreak'], ['cfgInjKeywords','enable_injection_keywords'],
  ['cfgInjPatterns','enable_injection_patterns'], ['cfgPersonaConflict','enable_persona_conflict'],
  ['cfgHate','enable_hate_detection'], ['cfgHarass','enable_harassment_detection'],
  ['cfgMalLink','enable_malicious_link'], ['cfgEncoded','enable_encoded_detection'],
  ['cfgPersonaConsist','enable_persona_consistency'],
];
const ACTION_CN = {block:'拦截', rewrite:'仅去除危险内容', mark:'标注放行', observe:'观察'};

function linesToText(arr){return (arr||[]).join('\\n');}
function textToLines(t){return t.split('\\n').map(s=>s.trim()).filter(s=>s);}

async function refresh(){
  try{
    const s = await (await api('/api/stats')).json();
    document.getElementById('statCards').innerHTML = Object.entries(s.by_action).map(([k,v])=>
      `<div class="card"><div class="num">${v}</div><div class="lbl">${ACTION_CN[k]||k}</div></div>`).join('')
      + `<div class="card"><div class="num">${s.total_intercepts}</div><div class="lbl">总拦截</div></div>`;

    const logs = await (await api('/api/logs?limit=20')).json();
    document.getElementById('logTable').querySelector('tbody').innerHTML = logs.map(e=>
      `<tr><td class="mono">${e.time_str}</td><td class="mono">${e.user_id}</td><td>${ACTION_CN[e.action]||e.action}</td><td>${e.reason}</td></tr>`).join('')
      || `<tr><td colspan="4" class="empty">暂无拦截记录</td></tr>`;

    const cfg = await (await api('/api/config')).json();
    document.getElementById('cfgSens').value = cfg.defense_sensitivity;
    document.getElementById('cfgAction').value = cfg.defense_action;
    document.getElementById('cfgReview').value = cfg.llm_review;
    document.getElementById('cfgPostProtect').value = cfg.post_defense_protection;
    document.getElementById('cfgAutoBan').checked = !!cfg.auto_ban;
    document.getElementById('cfgBanDuration').value = cfg.ban_duration;
    document.getElementById('cfgWhitelist').value = linesToText(cfg.whitelist);
    document.getElementById('cfgBlacklist').value = linesToText(cfg.blacklist);
    document.getElementById('cfgInputWords').value = linesToText(cfg.input_blacklist_words);
    document.getElementById('cfgOutputWords').value = linesToText(cfg.output_blacklist_words);
    document.getElementById('cfgOptimize').checked = !!cfg.enable_optimize;
    document.getElementById('cfgAutoBackup').checked = !!cfg.enable_auto_backup;
    document.getElementById('cfgCheckMode').value = cfg.check_mode;
    document.getElementById('cfgWarningTemplate').value = cfg.warning_template || '';
    document.getElementById('cfgNoticeTemplate').value = cfg.notice_template || '';
    document.getElementById('cfgTimezone').value = cfg.timezone;
    PERCEPTION.forEach(([id,key])=>{document.getElementById(id).checked = !!cfg[key];});
    DETECT.forEach(([id,key])=>{document.getElementById(id).checked = !!cfg[key];});
    renderIdMap(cfg.id_map_list || []);

    const bans = await (await api('/api/bans')).json();
    document.getElementById('banTable').querySelector('tbody').innerHTML = bans.map(b=>
      `<tr><td class="mono">${b.user_id}</td><td>${b.remaining}</td><td><button class="ghost" onclick="unban('${b.user_id}')">解封</button></td></tr>`).join('')
      || `<tr><td colspan="3" class="empty">封禁列表为空</td></tr>`;
  }catch(e){}
}

async function saveConfig(){
  const body = {
    defense_sensitivity: document.getElementById('cfgSens').value,
    defense_action: document.getElementById('cfgAction').value,
    llm_review: document.getElementById('cfgReview').value,
    post_defense_protection: document.getElementById('cfgPostProtect').value,
    auto_ban: document.getElementById('cfgAutoBan').checked,
    ban_duration: parseInt(document.getElementById('cfgBanDuration').value) || 0,
    whitelist: textToLines(document.getElementById('cfgWhitelist').value),
    blacklist: textToLines(document.getElementById('cfgBlacklist').value),
    input_blacklist_words: textToLines(document.getElementById('cfgInputWords').value),
    output_blacklist_words: textToLines(document.getElementById('cfgOutputWords').value),
    enable_optimize: document.getElementById('cfgOptimize').checked,
    enable_auto_backup: document.getElementById('cfgAutoBackup').checked,
    check_mode: document.getElementById('cfgCheckMode').value,
    id_map_list: collectIdMap(),
    warning_template: document.getElementById('cfgWarningTemplate').value,
    notice_template: document.getElementById('cfgNoticeTemplate').value,
    timezone: document.getElementById('cfgTimezone').value.trim() || 'Asia/Shanghai',
  };
  PERCEPTION.forEach(([id,key])=>{body[key] = document.getElementById(id).checked;});
  DETECT.forEach(([id,key])=>{body[key] = document.getElementById(id).checked;});
  const r = await fetch('/api/config?key=' + encodeURIComponent(KEY), {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const m = document.getElementById('cfgMsg');
  m.className = 'msg ' + (r.ok?'ok':'err'); m.textContent = r.ok?'已保存':'保存失败'; refresh();
}

function renderIdMap(list){
  document.getElementById('idMapList').innerHTML = '';
  (list||[]).forEach(item => addIdMapRow(item.nickname||'', item.user_id||''));
}
function addIdMapRow(nick, uid){
  const c = document.getElementById('idMapList');
  const row = document.createElement('div');
  row.className = 'idmap-row';
  row.innerHTML = '<input class="idmap-nick" placeholder="昵称"><input class="idmap-id" placeholder="预期真实 ID"><button class="danger" onclick="this.parentElement.remove()">删</button>';
  row.querySelector('.idmap-nick').value = nick || '';
  row.querySelector('.idmap-id').value = uid || '';
  c.appendChild(row);
}
function collectIdMap(){
  const list = [];
  document.querySelectorAll('#idMapList .idmap-row').forEach(r=>{
    const nick = r.querySelector('.idmap-nick').value.trim();
    const uid = r.querySelector('.idmap-id').value.trim();
    if(nick && uid) list.push({__template_key:'id_map_template', nickname:nick, user_id:uid});
  });
  return list;
}

async function doBan(){
  const id = document.getElementById('banId').value; const min = document.getElementById('banMin').value;
  if(!id) return;
  await fetch(`/api/ban?key=${encodeURIComponent(KEY)}&user_id=${encodeURIComponent(id)}&minutes=${min}`, {method:'POST'});
  document.getElementById('banId').value=''; refresh();
}
async function unban(id){
  await fetch(`/api/unban?key=${encodeURIComponent(KEY)}&user_id=${encodeURIComponent(id)}`, {method:'POST'});
  refresh();
}
async function rollbackPersonas(){
  const r = await fetch('/api/rollback?key=' + encodeURIComponent(KEY), {method:'POST'});
  const d = await r.json().catch(()=>({}));
  const m = document.getElementById('rollbackMsg');
  m.className = 'msg ' + (r.ok?'ok':'err');
  m.textContent = r.ok ? (d.rolled ? `已回滚 ${d.rolled} 个人设` : '没有可回滚的备份') : '回滚失败';
}
boot();
</script>
</body>
</html>"""


class WebUIServer:
    """aiohttp 管理面板服务。

    持有配置、封禁管理器和拦截日志的引用，读写都走这些对象，
    页面本身不保存状态，刷新即最新。
    """

    def __init__(self, config: dict, ban_manager, incident_log, password: str = "", context=None):
        self.config = config
        self.ban_manager = ban_manager
        self.incident_log = incident_log
        self.password = password or "promptguardian"
        self.context = context
        self._runner = None
        self._site = None

    def _check_key(self, request) -> bool:
        """校验 ?key= 参数是否匹配，不匹配返回 401。"""
        return request.query.get("key", "") == self.password

    def _unauthorized(self):
        return web.Response(status=401, text="unauthorized")

    # ---------- 页面 ----------

    async def _index(self, request):
        if not self._check_key(request):
            return self._unauthorized()
        return web.Response(text=_INDEX_HTML, content_type="text/html")

    # ---------- API ----------

    async def _api_stats(self, request):
        if not self._check_key(request):
            return self._unauthorized()
        return web.json_response(self.incident_log.stats())

    async def _api_logs(self, request):
        if not self._check_key(request):
            return self._unauthorized()
        try:
            limit = int(request.query.get("limit", "20"))
        except ValueError:
            limit = 20
        items = self.incident_log.recent(limit)
        for e in items:
            e["time_str"] = datetime.fromtimestamp(e["time"]).strftime("%m-%d %H:%M:%S")
        return web.json_response(items)

    async def _api_config(self, request):
        if not self._check_key(request):
            return self._unauthorized()
        if request.method == "GET":
            return web.json_response({
                "defense_sensitivity": self.config.get("defense_sensitivity", "medium"),
                "defense_action": self.config.get("defense_action", "block"),
                "post_defense_protection": self.config.get("post_defense_protection", "reread"),
                "auto_ban": self.config.get("auto_ban", False),
                "ban_duration": self.config.get("ban_duration", 60),
                "blacklist": self.config.get("blacklist") or [],
                "whitelist": self.config.get("whitelist") or [],
                "llm_review": self.config.get("llm_review", "risk"),
                "input_blacklist_words": self.config.get("input_blacklist_words") or [],
                "output_blacklist_words": self.config.get("output_blacklist_words") or [],
                "enable_jailbreak": self.config.get("enable_jailbreak", True),
                "enable_injection_keywords": self.config.get("enable_injection_keywords", True),
                "enable_injection_patterns": self.config.get("enable_injection_patterns", True),
                "enable_persona_conflict": self.config.get("enable_persona_conflict", True),
                "enable_hate_detection": self.config.get("enable_hate_detection", True),
                "enable_harassment_detection": self.config.get("enable_harassment_detection", True),
                "enable_malicious_link": self.config.get("enable_malicious_link", True),
                "enable_encoded_detection": self.config.get("enable_encoded_detection", True),
                "enable_persona_consistency": self.config.get("enable_persona_consistency", True),
                "enable_optimize": self.config.get("enable_optimize", False),
                "enable_auto_backup": self.config.get("enable_auto_backup", True),
                "id_map_list": self.config.get("id_map_list") or [],
                "check_mode": self.config.get("check_mode", "exact"),
                "warning_template": self.config.get("warning_template", ""),
                "notice_template": self.config.get("notice_template", ""),
                "timezone": self.config.get("timezone", "Asia/Shanghai"),
                "enable_platform": self.config.get("enable_platform", True),
                "enable_date": self.config.get("enable_date", True),
                "enable_weekday": self.config.get("enable_weekday", True),
                "enable_time_period": self.config.get("enable_time_period", True),
                "enable_solar_term": self.config.get("enable_solar_term", False),
                "enable_lunar": self.config.get("enable_lunar", False),
                "enable_holiday": self.config.get("enable_holiday", False),
            })
        # POST 更新配置
        try:
            body = await request.json()
        except Exception:
            return web.Response(status=400, text="bad json")
        for key in _SCALAR_KEYS:
            if key in body:
                self.config[key] = str(body[key])
        for key in _BOOL_KEYS:
            if key in body:
                self.config[key] = bool(body[key])
        for key in _INT_KEYS:
            if key in body:
                try:
                    self.config[key] = int(body[key])
                except (TypeError, ValueError):
                    pass
        for key in _LIST_KEYS:
            if key in body:
                self.config[key] = list(body[key]) if isinstance(body[key], list) else []
        # AstrBotConfig 需要显式 save 才会落盘，普通 dict 则跳过
        save = getattr(self.config, "save_config", None)
        if callable(save):
            save()
        return web.json_response({"ok": True})

    async def _api_bans(self, request):
        if not self._check_key(request):
            return self._unauthorized()
        bans = self.ban_manager.list_bans()
        for b in bans:
            rem = b["remaining"]
            b["remaining"] = "永久" if rem == -1 else f"{rem // 60} 分钟"
        return web.json_response(bans)

    async def _api_ban(self, request):
        if not self._check_key(request):
            return self._unauthorized()
        user_id = request.query.get("user_id", "")
        try:
            minutes = int(request.query.get("minutes", "0"))
        except ValueError:
            minutes = 0
        if user_id:
            self.ban_manager.ban(user_id, minutes)
            return web.json_response({"ok": True})
        return web.Response(status=400, text="missing user_id")

    async def _api_unban(self, request):
        if not self._check_key(request):
            return self._unauthorized()
        user_id = request.query.get("user_id", "")
        self.ban_manager.unban(user_id)
        return web.json_response({"ok": True})

    async def _api_rollback(self, request):
        if not self._check_key(request):
            return self._unauthorized()
        rolled = 0
        if self.context is not None:
            try:
                from ..stages.optimizer import rollback_personas
                rolled = rollback_personas(self.context)
            except Exception:
                rolled = 0
        return web.json_response({"ok": True, "rolled": rolled})

    # ---------- 生命周期 ----------

    async def start(self, host: str = "0.0.0.0", port: int = 6187):
        app = web.Application()
        app.router.add_get("/", self._index)
        app.router.add_get("/api/stats", self._api_stats)
        app.router.add_get("/api/logs", self._api_logs)
        app.router.add_get("/api/config", self._api_config)
        app.router.add_post("/api/config", self._api_config)
        app.router.add_get("/api/bans", self._api_bans)
        app.router.add_post("/api/ban", self._api_ban)
        app.router.add_post("/api/unban", self._api_unban)
        app.router.add_post("/api/rollback", self._api_rollback)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host, port)
        await self._site.start()
        logger.info("[aPromptGuardian] WebUI 已启动: http://%s:%s", host, port)

    async def stop(self):
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
