"""
Cyber Threat Explainer – Flask Web UI
Case 1: Suricata synthetic alerts with selectable LLM model and editable prompts.

Run:
    pip install flask openai pandas
    python flask_app.py
    Open http://localhost:5000
"""

import textwrap
import os
from dataclasses import dataclass

os.environ.setdefault(
    'OPENAI_API_KEY',
    ''
)

from flask import Flask, render_template, request, jsonify
from openai import OpenAI

app = Flask(__name__)

# ─── Available models ─────────────────────────────────────────────────────────
MODELS = [
    {"key": "qwen",    "label": "Qwen 3.5 · 27B",  "name": "qwen3.5:27b"},
    {"key": "llama33", "label": "LLaMA 3.3 · 70B", "name": "llama3.3:70b"},
    {"key": "llama4",  "label": "LLaMA 4 Scout",   "name": "llama4:scout"},
    {"key": "gemma",   "label": "Gemma 4 · 31B",   "name": "gemma4:31b"},
]
MODEL_MAP = {m["key"]: m["name"] for m in MODELS}
DEFAULT_MODEL_KEY = "llama33"

# ─── Default system prompt ────────────────────────────────────────────────────
DEFAULT_SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst embedded in a Security Operations "
    "Center (SOC). Your role is to explain threat detections in plain English "
    "so that Tier-1 analysts can understand exactly what happened. "
    "Provide a short explanation."
)

# ─── Data model ───────────────────────────────────────────────────────────────
@dataclass
class SuricataAlert:
    alert_id:    str
    timestamp:   str
    src_ip:      str
    dst_ip:      str
    dst_port:    int
    protocol:    str
    severity:    str
    attack_type: str
    rule_msg:    str
    rule_full:   str
    extra_ctx:   str = ""

# ─── Synthetic alerts ─────────────────────────────────────────────────────────
SYNTHETIC_ALERTS: list[SuricataAlert] = [
    SuricataAlert(
        alert_id="ALT-001", timestamp="2024-03-15 14:32:07",
        src_ip="185.220.101.47", dst_ip="10.0.0.25", dst_port=445,
        protocol="TCP", severity="critical", attack_type="Exploits",
        rule_msg="ET EXPLOIT MS17-010 EternalBlue SMB Echo Request",
        rule_full=(
            'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 '
            '(msg:"ET EXPLOIT MS17-010 EternalBlue SMB Echo Request"; '
            'flow:established,to_server; content:"|00 00 00 2f ff 53 4d 42|"; depth:9; '
            'reference:cve,2017-0144; classtype:attempted-admin; sid:2024218; rev:3;)'
        ),
    ),
    SuricataAlert(
        alert_id="ALT-002", timestamp="2024-03-15 15:10:44",
        src_ip="192.168.1.102", dst_ip="10.0.0.0/24", dst_port=0,
        protocol="TCP", severity="high", attack_type="Reconnaissance",
        rule_msg="ET SCAN Nmap SYN Scan Detected",
        rule_full=(
            'alert tcp $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"ET SCAN Nmap SYN Scan Detected"; flags:S; '
            'threshold: type both, track by_src, count 30, seconds 60; '
            'classtype:network-scan; sid:1228520; rev:5;)'
        ),
    ),
    SuricataAlert(
        alert_id="ALT-003", timestamp="2024-03-15 16:05:18",
        src_ip="91.108.4.200", dst_ip="10.0.0.80", dst_port=80,
        protocol="HTTP", severity="critical", attack_type="Shellcode",
        rule_msg="ET WEB_SERVER PHP Remote Code Execution via eval(base64_decode)",
        rule_full=(
            'alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS '
            '(msg:"ET WEB_SERVER PHP RCE via eval(base64_decode)"; '
            'content:"eval(base64_decode"; http_uri; '
            'pcre:"/eval\\(base64_decode/i"; '
            'classtype:web-application-attack; sid:2014829; rev:2;)'
        ),
    ),
    SuricataAlert(
        alert_id="ALT-004", timestamp="2024-03-15 17:22:33",
        src_ip="203.0.113.55", dst_ip="10.0.0.80", dst_port=443,
        protocol="TCP", severity="high", attack_type="DoS",
        rule_msg="ET DOS Slowloris HTTP Denial of Service Attempt",
        rule_full=(
            'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS '
            '(msg:"ET DOS Slowloris HTTP Denial of Service Attempt"; '
            'flow:to_server,established; content:"GET /"; '
            'threshold: type both, track by_src, count 200, seconds 10; '
            'classtype:denial-of-service; sid:2012887; rev:6;)'
        ),
    ),
    SuricataAlert(
        alert_id="ALT-005", timestamp="2024-03-15 18:50:01",
        src_ip="10.0.0.45", dst_ip="198.51.100.77", dst_port=4444,
        protocol="TCP", severity="medium", attack_type="Backdoor",
        rule_msg="ET MALWARE Possible Reverse Shell Beacon to C2",
        rule_full=(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
            '(msg:"ET MALWARE Possible Reverse Shell Beacon to C2"; '
            'flow:to_server,established; content:"cmd.exe"; nocase; '
            'detection_filter: track by_src, count 5, seconds 300; '
            'classtype:trojan-activity; sid:2019987; rev:4;)'
        ),
    ),
]

ALERT_MAP = {a.alert_id: a for a in SYNTHETIC_ALERTS}

SEV_BADGE = {
    'critical': 'danger',
    'high':     'warning',
    'medium':   'info',
    'low':      'success',
}

# ─── Prompt builder ───────────────────────────────────────────────────────────
def build_case1_prompt(alert: SuricataAlert) -> str:
    return textwrap.dedent(f"""
        A threat detection system has fired the following Suricata IDS alert.
        Explain it in plain English for a SOC analyst.

        ── ALERT DETAILS ──────────────────────────────────────────────────────
        Alert ID     : {alert.alert_id}
        Timestamp    : {alert.timestamp}
        Source IP    : {alert.src_ip}
        Destination  : {alert.dst_ip}:{alert.dst_port} ({alert.protocol})
        Attack type  : {alert.attack_type}
        Severity     : {alert.severity.upper()}
        Rule message : {alert.rule_msg}

        Full Suricata rule:
        {alert.rule_full}
        {"Extra context: " + alert.extra_ctx if alert.extra_ctx else ""}
        ───────────────────────────────────────────────────────────────────────
    """).strip()

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    alert_list = [
        {
            'id':       a.alert_id,
            'attack':   a.attack_type,
            'src_ip':   a.src_ip,
            'dst':      f"{a.dst_ip}:{a.dst_port}",
            'severity': a.severity,
            'badge':    SEV_BADGE.get(a.severity, 'secondary'),
            'rule_msg': a.rule_msg,
        }
        for a in SYNTHETIC_ALERTS
    ]
    return render_template(
        'index.html',
        alerts=alert_list,
        models=MODELS,
        default_model_key=DEFAULT_MODEL_KEY,
        default_system_prompt=DEFAULT_SYSTEM_PROMPT,
        first_alert_id=SYNTHETIC_ALERTS[0].alert_id,
    )


@app.route('/api/prompt', methods=['POST'])
def api_get_prompt():
    data = request.get_json(silent=True) or {}
    alert = ALERT_MAP.get(data.get('alert_id', ''))
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    return jsonify({'prompt': build_case1_prompt(alert)})


@app.route('/api/explain', methods=['POST'])
def api_explain():
    data = request.get_json(silent=True) or {}
    model_key   = data.get('model_key', DEFAULT_MODEL_KEY)
    sys_prompt  = (data.get('system_prompt') or DEFAULT_SYSTEM_PROMPT).strip()
    user_prompt = (data.get('user_prompt') or '').strip()
    max_tokens  = min(max(int(data.get('max_tokens', 300)), 50), 1000)

    model_name = MODEL_MAP.get(model_key)
    if not model_name:
        return jsonify({'error': f'Unknown model key: {model_key}'}), 400
    if not user_prompt:
        return jsonify({'error': 'User prompt is empty.'}), 400

    try:
        client = OpenAI(base_url="http://interweb.l3s.uni-hannover.de")
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user",   "content": user_prompt},
        ]
        resp = client.chat.completions.create(
            model=model_name,
            max_tokens=max_tokens,
            temperature=0.7,
            messages=messages,
        )
        explanation = resp.choices[0].message.content.strip()
        return jsonify({
            'explanation':   explanation,
            'model_name':    model_name,
            'system_prompt': sys_prompt,
            'user_prompt':   user_prompt,
            'max_tokens':    max_tokens,
        })
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5002)
