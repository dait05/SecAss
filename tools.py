"""安全情报分析工具集 —— Agent 可调用的分析工具"""

from __future__ import annotations
import re
import json
import ipaddress
from datetime import datetime


# ---------------------------------------------------------------------------
# 工具注册表
# ---------------------------------------------------------------------------
TOOL_REGISTRY: dict[str, dict] = {}


def register_tool(name: str, description: str, parameters: dict):
    """装饰器：将函数注册为 Agent 可调用的工具"""
    def decorator(func):
        TOOL_REGISTRY[name] = {
            "name": name,
            "description": description,
            "parameters": parameters,
            "func": func,
        }
        return func
    return decorator


# ---------------------------------------------------------------------------
# 工具实现
# ---------------------------------------------------------------------------

@register_tool(
    name="extract_iocs",
    description="从文本中提取安全威胁指标 (IOC)，包括 IP 地址、域名、URL、文件哈希、邮箱地址、CVE 编号等",
    parameters={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "需要提取 IOC 的原始文本"}
        },
        "required": ["text"],
    },
)
def extract_iocs(text: str) -> dict:
    """从文本中提取各类 IOC"""
    patterns = {
        "ipv4": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "ipv6": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|cn|ru|xyz|top|info|biz|cc|tk|ml|ga|cf|gq|pw)\b',
        "url": r'https?://[^\s<>"\']+',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha1": r'\b[a-fA-F0-9]{40}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
        "email": r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
        "cve": r'CVE-\d{4}-\d{4,}',
    }

    results = {}
    for ioc_type, pattern in patterns.items():
        matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
        if matches:
            results[ioc_type] = matches

    # 验证 IP 有效性
    if "ipv4" in results:
        valid_ips = []
        for ip in results["ipv4"]:
            try:
                addr = ipaddress.IPv4Address(ip)
                if not addr.is_private and not addr.is_loopback:
                    valid_ips.append(ip)
            except ipaddress.AddressValueError:
                pass
        results["ipv4_public"] = valid_ips

    results["_summary"] = {k: len(v) for k, v in results.items() if not k.startswith("_")}
    return results


@register_tool(
    name="analyze_log_entry",
    description="分析安全日志条目，识别异常行为模式（暴力破解、端口扫描、横向移动等）",
    parameters={
        "type": "object",
        "properties": {
            "log_text": {"type": "string", "description": "日志文本内容"}
        },
        "required": ["log_text"],
    },
)
def analyze_log_entry(log_text: str) -> dict:
    """分析日志条目，检测异常行为"""
    findings = []
    risk_score = 0

    # 暴力破解检测
    failed_logins = re.findall(r'(?:failed|invalid|unauthorized)\s+(?:login|password|auth)', log_text, re.I)
    if len(failed_logins) >= 3:
        findings.append({"type": "brute_force", "severity": "high", "detail": f"检测到 {len(failed_logins)} 次登录失败"})
        risk_score += 30

    # 端口扫描检测
    ports = re.findall(r'(?:port|dst_port|dport)[=:\s]+(\d+)', log_text, re.I)
    unique_ports = set(ports)
    if len(unique_ports) > 10:
        findings.append({"type": "port_scan", "severity": "high", "detail": f"检测到访问 {len(unique_ports)} 个不同端口"})
        risk_score += 25

    # 可疑命令检测
    suspicious_cmds = re.findall(
        r'(?:whoami|net\s+user|net\s+localgroup|mimikatz|powershell\s+-enc|certutil\s+-urlcache|'
        r'cmd\.exe\s+/c|wget|curl\s+.*\|.*sh|chmod\s+777|/etc/shadow|/etc/passwd|'
        r'nc\s+-[elvp]|ncat|reverse.*shell|bind.*shell)', log_text, re.I
    )
    if suspicious_cmds:
        findings.append({
            "type": "suspicious_command",
            "severity": "critical",
            "detail": f"发现可疑命令: {', '.join(set(suspicious_cmds)[:5])}"
        })
        risk_score += 40

    # 横向移动检测
    lateral = re.findall(r'(?:psexec|wmic|smbclient|evil-winrm|pass.the.hash|rdp|ssh.*@)', log_text, re.I)
    if lateral:
        findings.append({"type": "lateral_movement", "severity": "high", "detail": f"可能的横向移动: {', '.join(set(lateral)[:5])}"})
        risk_score += 30

    # 数据外传检测
    exfil = re.findall(r'(?:ftp\s+|scp\s+|base64.*>|curl.*-d|wget.*--post)', log_text, re.I)
    if exfil:
        findings.append({"type": "data_exfiltration", "severity": "high", "detail": "检测到潜在数据外传行为"})
        risk_score += 25

    return {
        "findings": findings,
        "risk_score": min(risk_score, 100),
        "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "medium" if risk_score >= 20 else "low",
        "total_indicators": len(findings),
    }


@register_tool(
    name="classify_threat",
    description="根据 MITRE ATT&CK 框架对威胁事件进行分类和标记",
    parameters={
        "type": "object",
        "properties": {
            "description": {"type": "string", "description": "威胁事件描述"}
        },
        "required": ["description"],
    },
)
def classify_threat(description: str) -> dict:
    """基于关键词映射到 MITRE ATT&CK 战术和技术"""
    mitre_mapping = {
        "initial_access": {
            "keywords": ["phishing", "钓鱼", "spearphish", "exploit public", "drive-by", "水坑攻击", "供应链"],
            "tactic_id": "TA0001",
            "techniques": ["T1566", "T1190", "T1189", "T1195"],
        },
        "execution": {
            "keywords": ["powershell", "cmd", "script", "macro", "wmi", "命令执行", "代码执行"],
            "tactic_id": "TA0002",
            "techniques": ["T1059", "T1204", "T1047"],
        },
        "persistence": {
            "keywords": ["registry", "scheduled task", "计划任务", "startup", "service", "后门", "backdoor", "webshell"],
            "tactic_id": "TA0003",
            "techniques": ["T1547", "T1053", "T1543"],
        },
        "privilege_escalation": {
            "keywords": ["privilege", "提权", "escalat", "sudo", "admin", "root", "uac bypass"],
            "tactic_id": "TA0004",
            "techniques": ["T1548", "T1068"],
        },
        "defense_evasion": {
            "keywords": ["obfuscat", "混淆", "encode", "加密", "disable", "bypass", "masquerad", "免杀"],
            "tactic_id": "TA0005",
            "techniques": ["T1027", "T1070", "T1036"],
        },
        "credential_access": {
            "keywords": ["password", "credential", "密码", "凭证", "mimikatz", "dump", "hash", "brute", "暴力破解", "kerberoast"],
            "tactic_id": "TA0006",
            "techniques": ["T1003", "T1110", "T1558"],
        },
        "lateral_movement": {
            "keywords": ["lateral", "横向", "psexec", "rdp", "remote", "smb", "wmic", "pass.the"],
            "tactic_id": "TA0008",
            "techniques": ["T1021", "T1570"],
        },
        "exfiltration": {
            "keywords": ["exfiltrat", "外传", "泄露", "upload", "数据窃取", "transfer", "c2", "c&c"],
            "tactic_id": "TA0010",
            "techniques": ["T1041", "T1048"],
        },
        "impact": {
            "keywords": ["ransom", "勒索", "encrypt", "destroy", "wipe", "ddos", "拒绝服务"],
            "tactic_id": "TA0040",
            "techniques": ["T1486", "T1485", "T1498"],
        },
    }

    desc_lower = description.lower()
    matched_tactics = []

    for tactic, info in mitre_mapping.items():
        for kw in info["keywords"]:
            if kw.lower() in desc_lower:
                matched_tactics.append({
                    "tactic": tactic,
                    "tactic_id": info["tactic_id"],
                    "techniques": info["techniques"],
                    "matched_keyword": kw,
                })
                break

    severity = "critical" if len(matched_tactics) >= 3 else "high" if len(matched_tactics) >= 2 else "medium" if matched_tactics else "low"

    return {
        "matched_tactics": matched_tactics,
        "severity": severity,
        "mitre_url": "https://attack.mitre.org/",
        "recommendation": "建议结合完整 ATT&CK 矩阵进行深入分析" if matched_tactics else "未匹配到明确战术，建议人工研判",
    }


@register_tool(
    name="summarize_intel",
    description="对安全情报报告进行结构化摘要，提取关键信息",
    parameters={
        "type": "object",
        "properties": {
            "report_text": {"type": "string", "description": "情报报告原文"}
        },
        "required": ["report_text"],
    },
)
def summarize_intel(report_text: str) -> dict:
    """提取情报报告的结构化摘要"""
    iocs = extract_iocs(report_text)
    threat_class = classify_threat(report_text)

    return {
        "iocs_extracted": iocs.get("_summary", {}),
        "threat_classification": threat_class,
        "text_length": len(report_text),
        "timestamp": datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# 工具描述（供 LLM system prompt 使用）
# ---------------------------------------------------------------------------

def get_tools_description() -> str:
    """生成供 LLM 理解的工具列表描述"""
    lines = []
    for name, tool in TOOL_REGISTRY.items():
        params = json.dumps(tool["parameters"], ensure_ascii=False, indent=2)
        lines.append(f"### {name}\n{tool['description']}\n参数: {params}\n")
    return "\n".join(lines)


def get_openai_tools_schema() -> list[dict]:
    """生成 OpenAI function-calling 格式的工具 schema"""
    tools = []
    for name, tool in TOOL_REGISTRY.items():
        tools.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["parameters"],
            },
        })
    return tools


def call_tool(name: str, arguments: dict) -> dict:
    """根据名称调用工具"""
    if name not in TOOL_REGISTRY:
        return {"error": f"未知工具: {name}"}
    try:
        func = TOOL_REGISTRY[name]["func"]
        return func(**arguments)
    except Exception as e:
        return {"error": f"工具执行失败: {str(e)}"}
