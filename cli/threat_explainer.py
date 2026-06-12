"""
=============================================================================
Cyber Threat Explainer
=============================================================================
Reads Suricata-style alerts (synthetic) and NF-UNSW-NB15-v2 flow records,
then calls an LLM to generate human-readable explanations.

TWO CASES:
  Case 1 – Suricata rule match + source IP only
  Case 2 – Suricata rule match + source IP + full NF-UNSW-NB15 flow features

HOW TO USE:
  1. Install deps:
       pip install pandas anthropic openai   # add whichever LLM SDK you use

  2. Set your LLM backend in LLMClient below (Anthropic, OpenAI, or a custom
     HTTP endpoint).  Only one block needs to be active.

  3. Run:
       # Run both cases on synthetic data
       python threat_explainer.py

       # Run Case 2 on real CSV (NF-UNSW-NB15-v2.csv must exist)
       python threat_explainer.py --csv NF-UNSW-NB15-v2.csv --attack DoS --n 3

  CLI options:
       --csv      PATH     path to NF-UNSW-NB15-v2 CSV file
       --attack   NAME     filter by attack label (DoS, Exploits, Worms …)
       --n        INT      how many CSV rows to explain (default 3)
       --case     1|2|all  which case to run (default all)
       --out      PATH     write JSON results to file (optional)
=============================================================================
"""

import argparse
import json
import sys
import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
import openai
from openai import OpenAI
import pandas as pd
import os
os.environ['OPENAI_API_KEY'] = ''


# ─────────────────────────────────────────────────────────────────────────────
# 1.  LLM CLIENT  –  edit this section for your provider
# ─────────────────────────────────────────────────────────────────────────────

class LLMClient:
    """
    Swap in your own LLM here.  Three providers are shown; uncomment one.
    """

    def __init__(self):
        # ── Option A: Anthropic ──────────────────────────────────────────────
        self._client = OpenAI(base_url="http://interweb.l3s.uni-hannover.de")
        self._provider = "interweb"
        self._model = "llama3.3:70b" 
        #self._model = "llama3.2:1b-instruct-fp16"         # or claude-sonnet-4-5, etc.
        self._model = "gemma2:9b"
        models = self._client.models.list()
        print(models)
    def complete(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 100) -> str:

        if self._provider == "interweb":
            resp = self._client.chat.completions.create(
                model=self._model,
                max_tokens=max_tokens,
                temperature=0.7,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
            )
            return resp.choices[0].message.content.strip()

        raise ValueError(f"Unknown provider: {self._provider}")


# ─────────────────────────────────────────────────────────────────────────────
# 2.  DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SuricataAlert:
    """A single Suricata-style IDS alert (synthetic or from a real sensor)."""
    alert_id:    str
    timestamp:   str
    src_ip:      str
    dst_ip:      str
    dst_port:    int
    protocol:    str
    severity:    str          # critical / high / medium / low
    attack_type: str          # Exploits, DoS, Reconnaissance …
    rule_msg:    str          # human-readable msg field
    rule_full:   str          # full Suricata rule text
    extra_ctx:   str = ""     # optional free-text context


@dataclass
class FlowRecord:
    """One row from the NF-UNSW-NB15-v2 dataset."""
    IPV4_SRC_ADDR:                 str
    L4_SRC_PORT:                   int
    IPV4_DST_ADDR:                 str
    L4_DST_PORT:                   int
    PROTOCOL:                      int
    L7_PROTO:                      float
    IN_BYTES:                      int
    IN_PKTS:                       int
    OUT_BYTES:                     int
    OUT_PKTS:                      int
    TCP_FLAGS:                     int
    CLIENT_TCP_FLAGS:              int
    SERVER_TCP_FLAGS:              int
    FLOW_DURATION_MILLISECONDS:    int
    DURATION_IN:                   int
    DURATION_OUT:                  int
    MIN_TTL:                       int
    MAX_TTL:                       int
    LONGEST_FLOW_PKT:              int
    SHORTEST_FLOW_PKT:             int
    MIN_IP_PKT_LEN:                int
    MAX_IP_PKT_LEN:                int
    SRC_TO_DST_SECOND_BYTES:       float
    DST_TO_SRC_SECOND_BYTES:       float
    RETRANSMITTED_IN_BYTES:        int
    RETRANSMITTED_IN_PKTS:         int
    RETRANSMITTED_OUT_BYTES:       int
    RETRANSMITTED_OUT_PKTS:        int
    SRC_TO_DST_AVG_THROUGHPUT:     int
    DST_TO_SRC_AVG_THROUGHPUT:     int
    NUM_PKTS_UP_TO_128_BYTES:      int
    NUM_PKTS_128_TO_256_BYTES:     int
    NUM_PKTS_256_TO_512_BYTES:     int
    NUM_PKTS_512_TO_1024_BYTES:    int
    NUM_PKTS_1024_TO_1514_BYTES:   int
    TCP_WIN_MAX_IN:                int
    TCP_WIN_MAX_OUT:               int
    ICMP_TYPE:                     int
    ICMP_IPV4_TYPE:                int
    DNS_QUERY_ID:                  int
    DNS_QUERY_TYPE:                int
    DNS_TTL_ANSWER:                int
    FTP_COMMAND_RET_CODE:          float
    Label:                         str   # Benign / Exploits / DoS / …
    Attack:                        int   # 0 = benign, 1 = attack


@dataclass
class ExplanationResult:
    """Holds one explained event."""
    case:          int
    event_id:      str
    attack_type:   str
    severity:      str
    src_ip:        str
    dst_ip:        str
    rule_msg:      str
    explanation:   str
    timestamp:     str = field(default_factory=lambda: datetime.now().isoformat())


# ─────────────────────────────────────────────────────────────────────────────
# 3.  SYNTHETIC SURICATA ALERTS (5 examples covering major attack categories)
# ─────────────────────────────────────────────────────────────────────────────

SYNTHETIC_ALERTS: list[SuricataAlert] = [
    SuricataAlert(
        alert_id="ALT-001",
        timestamp="2024-03-15 14:32:07",
        src_ip="185.220.101.47",
        dst_ip="10.0.0.25",
        dst_port=445,
        protocol="TCP",
        severity="critical",
        attack_type="Exploits",
        rule_msg="ET EXPLOIT MS17-010 EternalBlue SMB Echo Request",
        rule_full=(
            'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 '
            '(msg:"ET EXPLOIT MS17-010 EternalBlue SMB Echo Request"; '
            'flow:established,to_server; '
            'content:"|00 00 00 2f ff 53 4d 42|"; depth:9; '
            'reference:cve,2017-0144; classtype:attempted-admin; '
            'sid:2024218; rev:3;)'
        ),
    ),
    SuricataAlert(
        alert_id="ALT-002",
        timestamp="2024-03-15 15:10:44",
        src_ip="192.168.1.102",
        dst_ip="10.0.0.0/24",
        dst_port=0,
        protocol="TCP",
        severity="high",
        attack_type="Reconnaissance",
        rule_msg="ET SCAN Nmap SYN Scan Detected",
        rule_full=(
            'alert tcp $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"ET SCAN Nmap SYN Scan Detected"; flags:S; '
            'threshold: type both, track by_src, count 30, seconds 60; '
            'classtype:network-scan; sid:1228520; rev:5;)'
        ),
    ),
    SuricataAlert(
        alert_id="ALT-003",
        timestamp="2024-03-15 16:05:18",
        src_ip="91.108.4.200",
        dst_ip="10.0.0.80",
        dst_port=80,
        protocol="HTTP",
        severity="critical",
        attack_type="Shellcode",
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
        alert_id="ALT-004",
        timestamp="2024-03-15 17:22:33",
        src_ip="203.0.113.55",
        dst_ip="10.0.0.80",
        dst_port=443,
        protocol="TCP",
        severity="high",
        attack_type="DoS",
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
        alert_id="ALT-005",
        timestamp="2024-03-15 18:50:01",
        src_ip="10.0.0.45",
        dst_ip="198.51.100.77",
        dst_port=4444,
        protocol="TCP",
        severity="medium",
        attack_type="Backdoor",
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


# ─────────────────────────────────────────────────────────────────────────────
# 4.  SYNTHETIC NF-UNSW-NB15-v2 ROWS  (one per attack category)
# ─────────────────────────────────────────────────────────────────────────────
# Each dict exactly matches the 45-column schema.  Add matching Suricata rule
# text so Case 2 has both data sources.

_FLOW_DEFAULTS = dict(
    CLIENT_TCP_FLAGS=0, SERVER_TCP_FLAGS=0, DURATION_IN=0, DURATION_OUT=0,
    MIN_IP_PKT_LEN=40, MAX_IP_PKT_LEN=1460, ICMP_TYPE=0, ICMP_IPV4_TYPE=0,
    DNS_QUERY_ID=0, DNS_QUERY_TYPE=0, DNS_TTL_ANSWER=0, FTP_COMMAND_RET_CODE=0.0,
)

SYNTHETIC_FLOWS: list[dict] = [
    # ── Exploits ──────────────────────────────────────────────────────────────
    dict(
        IPV4_SRC_ADDR="175.45.176.1", L4_SRC_PORT=50321,
        IPV4_DST_ADDR="149.171.126.9", L4_DST_PORT=80,
        PROTOCOL=6, L7_PROTO=7.0,
        IN_BYTES=48200,  IN_PKTS=62,
        OUT_BYTES=12400, OUT_PKTS=28,
        TCP_FLAGS=27, FLOW_DURATION_MILLISECONDS=1840,
        MIN_TTL=54, MAX_TTL=64,
        LONGEST_FLOW_PKT=1460, SHORTEST_FLOW_PKT=40,
        SRC_TO_DST_SECOND_BYTES=26195652.0, DST_TO_SRC_SECOND_BYTES=6739130.0,
        RETRANSMITTED_IN_BYTES=4380, RETRANSMITTED_IN_PKTS=3,
        RETRANSMITTED_OUT_BYTES=0, RETRANSMITTED_OUT_PKTS=0,
        SRC_TO_DST_AVG_THROUGHPUT=26195652, DST_TO_SRC_AVG_THROUGHPUT=6739130,
        NUM_PKTS_UP_TO_128_BYTES=14, NUM_PKTS_128_TO_256_BYTES=4,
        NUM_PKTS_256_TO_512_BYTES=8,  NUM_PKTS_512_TO_1024_BYTES=10,
        NUM_PKTS_1024_TO_1514_BYTES=26,
        TCP_WIN_MAX_IN=65535, TCP_WIN_MAX_OUT=8192,
        Label="Exploits", Attack=1,
        _rule_msg="ET EXPLOIT CVE-2021-44228 Log4j RCE Attempt",
        _rule_full='alert http any any -> any any (msg:"ET EXPLOIT CVE-2021-44228 Log4j RCE"; content:"${jndi:"; classtype:attempted-admin; sid:2034647; rev:1;)',
        **_FLOW_DEFAULTS,
    ),
    # ── DoS ───────────────────────────────────────────────────────────────────
    dict(
        IPV4_SRC_ADDR="59.166.0.9", L4_SRC_PORT=32768,
        IPV4_DST_ADDR="149.171.126.6", L4_DST_PORT=80,
        PROTOCOL=6, L7_PROTO=7.0,
        IN_BYTES=1850000, IN_PKTS=14820,
        OUT_BYTES=2400,   OUT_PKTS=38,
        TCP_FLAGS=2, FLOW_DURATION_MILLISECONDS=5200,
        MIN_TTL=54, MAX_TTL=54,
        LONGEST_FLOW_PKT=128, SHORTEST_FLOW_PKT=40,
        SRC_TO_DST_SECOND_BYTES=355769230.0, DST_TO_SRC_SECOND_BYTES=461538.0,
        RETRANSMITTED_IN_BYTES=0, RETRANSMITTED_IN_PKTS=0,
        RETRANSMITTED_OUT_BYTES=0, RETRANSMITTED_OUT_PKTS=0,
        SRC_TO_DST_AVG_THROUGHPUT=355769230, DST_TO_SRC_AVG_THROUGHPUT=461538,
        NUM_PKTS_UP_TO_128_BYTES=14820, NUM_PKTS_128_TO_256_BYTES=0,
        NUM_PKTS_256_TO_512_BYTES=0,    NUM_PKTS_512_TO_1024_BYTES=0,
        NUM_PKTS_1024_TO_1514_BYTES=0,
        TCP_WIN_MAX_IN=512, TCP_WIN_MAX_OUT=8192,
        Label="DoS", Attack=1,
        _rule_msg="ET DOS TCP SYN Flood Detected",
        _rule_full='alert tcp any any -> $HOME_NET 80 (msg:"ET DOS TCP SYN Flood"; flags:S; threshold: type both, track by_src, count 500, seconds 5; classtype:denial-of-service; sid:2002910; rev:3;)',
        **_FLOW_DEFAULTS,
    ),
    # ── Reconnaissance ────────────────────────────────────────────────────────
    dict(
        IPV4_SRC_ADDR="175.45.176.2", L4_SRC_PORT=44123,
        IPV4_DST_ADDR="149.171.126.7", L4_DST_PORT=22,
        PROTOCOL=6, L7_PROTO=92.0,
        IN_BYTES=940,  IN_PKTS=18,
        OUT_BYTES=720, OUT_PKTS=12,
        TCP_FLAGS=26, FLOW_DURATION_MILLISECONDS=82400,
        MIN_TTL=54, MAX_TTL=64,
        LONGEST_FLOW_PKT=94, SHORTEST_FLOW_PKT=40,
        SRC_TO_DST_SECOND_BYTES=11408.0, DST_TO_SRC_SECOND_BYTES=8737.0,
        RETRANSMITTED_IN_BYTES=0, RETRANSMITTED_IN_PKTS=0,
        RETRANSMITTED_OUT_BYTES=0, RETRANSMITTED_OUT_PKTS=0,
        SRC_TO_DST_AVG_THROUGHPUT=11408, DST_TO_SRC_AVG_THROUGHPUT=8737,
        NUM_PKTS_UP_TO_128_BYTES=30, NUM_PKTS_128_TO_256_BYTES=0,
        NUM_PKTS_256_TO_512_BYTES=0,  NUM_PKTS_512_TO_1024_BYTES=0,
        NUM_PKTS_1024_TO_1514_BYTES=0,
        TCP_WIN_MAX_IN=29200, TCP_WIN_MAX_OUT=14480,
        Label="Reconnaissance", Attack=1,
        _rule_msg="ET SCAN SSH Brute Force Login Attempt",
        _rule_full='alert tcp any any -> any 22 (msg:"ET SCAN SSH Brute Force"; content:"SSH"; threshold: type both, track by_src, count 10, seconds 60; classtype:network-scan; sid:2001219; rev:4;)',
        **_FLOW_DEFAULTS,
    ),
    # ── Worms ─────────────────────────────────────────────────────────────────
    dict(
        IPV4_SRC_ADDR="10.0.0.77", L4_SRC_PORT=1025,
        IPV4_DST_ADDR="10.0.0.88", L4_DST_PORT=445,
        PROTOCOL=6, L7_PROTO=1.0,
        IN_BYTES=24680, IN_PKTS=42,
        OUT_BYTES=18900, OUT_PKTS=36,
        TCP_FLAGS=24, FLOW_DURATION_MILLISECONDS=340,
        MIN_TTL=128, MAX_TTL=128,
        LONGEST_FLOW_PKT=1460, SHORTEST_FLOW_PKT=52,
        SRC_TO_DST_SECOND_BYTES=72588235.0, DST_TO_SRC_SECOND_BYTES=55588235.0,
        RETRANSMITTED_IN_BYTES=1460, RETRANSMITTED_IN_PKTS=1,
        RETRANSMITTED_OUT_BYTES=0,   RETRANSMITTED_OUT_PKTS=0,
        SRC_TO_DST_AVG_THROUGHPUT=72588235, DST_TO_SRC_AVG_THROUGHPUT=55588235,
        NUM_PKTS_UP_TO_128_BYTES=8,  NUM_PKTS_128_TO_256_BYTES=0,
        NUM_PKTS_256_TO_512_BYTES=2, NUM_PKTS_512_TO_1024_BYTES=4,
        NUM_PKTS_1024_TO_1514_BYTES=64,
        TCP_WIN_MAX_IN=65535, TCP_WIN_MAX_OUT=65535,
        Label="Worms", Attack=1,
        _rule_msg="ET MALWARE WannaCry/NotPetya Lateral Movement SMB",
        _rule_full='alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"ET MALWARE WannaCry Lateral Movement SMB"; content:"|ff 53 4d 42 72 00 00 00|"; classtype:trojan-activity; sid:2024217; rev:2;)',
        **_FLOW_DEFAULTS,
    ),
    # ── Generic ───────────────────────────────────────────────────────────────
    dict(
        IPV4_SRC_ADDR="203.0.113.22", L4_SRC_PORT=53214,
        IPV4_DST_ADDR="149.171.126.1", L4_DST_PORT=53,
        PROTOCOL=17, L7_PROTO=5.0,
        IN_BYTES=680,  IN_PKTS=8,
        OUT_BYTES=4920, OUT_PKTS=14,
        TCP_FLAGS=0, FLOW_DURATION_MILLISECONDS=12000,
        MIN_TTL=60, MAX_TTL=64,
        LONGEST_FLOW_PKT=512, SHORTEST_FLOW_PKT=60,
        SRC_TO_DST_SECOND_BYTES=56666.0, DST_TO_SRC_SECOND_BYTES=410000.0,
        RETRANSMITTED_IN_BYTES=0, RETRANSMITTED_IN_PKTS=0,
        RETRANSMITTED_OUT_BYTES=0, RETRANSMITTED_OUT_PKTS=0,
        SRC_TO_DST_AVG_THROUGHPUT=56666, DST_TO_SRC_AVG_THROUGHPUT=410000,
        NUM_PKTS_UP_TO_128_BYTES=10, NUM_PKTS_128_TO_256_BYTES=0,
        NUM_PKTS_256_TO_512_BYTES=6, NUM_PKTS_512_TO_1024_BYTES=6,
        NUM_PKTS_1024_TO_1514_BYTES=0,
        TCP_WIN_MAX_IN=0, TCP_WIN_MAX_OUT=0,
        Label="Generic", Attack=1,
        _rule_msg="ET DNS Tunneling / C2 Domain Query Pattern",
        _rule_full='alert udp any any -> any 53 (msg:"ET DNS C2 Tunneling Pattern"; content:"|00 01 00 00 00 00 00 00|"; depth:8; threshold: type threshold, track by_src, count 50, seconds 60; classtype:trojan-activity; sid:2027865; rev:1;)',
        **_FLOW_DEFAULTS,
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# 5.  PROMPT BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

# SYSTEM_PROMPT = (
#     "You are a senior cybersecurity analyst embedded in a Security Operations "
#     "Center (SOC). Your role is to explain threat detections in plain English "
#     "so that Tier-1 analysts can understand exactly what happened, why it is "
#     "dangerous, and what to do next. Be precise, concise, and reference "
#     "specific technical values when they are provided. Write in flowing "
#     "paragraphs without bullet points or markdown headers.Provide a short explanation"
# )

SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst embedded in a Security Operations "
    "Center (SOC). Your role is to explain threat detections in plain English "
    "so that Tier-1 analysts can understand exactly what happened. Provide a short explanation."
)

def build_case1_prompt(alert: SuricataAlert) -> str:
    """Case 1: rule match + IP – no flow features."""
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
        # Your explanation must cover:
        # 1. What this attack is and why it is dangerous (2-3 sentences).
        # 2. What specifically the rule matched and why that byte pattern or
        #    behavior is suspicious (1-2 sentences).
        # 3. The attacker's likely goal given the destination IP and port (1 sentence).
        # 4. The immediate recommended action for the analyst (1-2 sentences).

def build_case2_prompt(alert: SuricataAlert, flow: dict) -> str:
    """Case 2: rule match + IP + full NF-UNSW-NB15-v2 flow features."""
    # Build a readable feature block (exclude private _rule_* keys)
    feature_lines = "\n".join(
        f"  {k:<40} = {v}"
        for k, v in flow.items()
        if not k.startswith("_") and k not in ("Label", "Attack")
    )
    return textwrap.dedent(f"""
        A network flow has been classified as a '{flow.get("Label","UNKNOWN")}' attack
        by a machine-learning model trained on the NF-UNSW-NB15-v2 dataset.
        A Suricata IDS rule has also triggered on the same traffic.
        Explain this detection in plain English for a SOC analyst.

        ── SURICATA RULE MATCH ─────────────────────────────────────────────────
        Rule message : {alert.rule_msg}
        Full rule    : {alert.rule_full}
        Source IP    : {alert.src_ip}
        Attack label : {flow.get("Label","?")}
        Severity     : {alert.severity.upper()}
        ───────────────────────────────────────────────────────────────────────

        ── NF-UNSW-NB15-v2 NETWORK FLOW FEATURES ──────────────────────────────
{feature_lines}
        ───────────────────────────────────────────────────────────────────────

        Your explanation must cover:
        1. What attack was detected and which specific feature values (e.g.
           IN_BYTES, IN_PKTS, FLOW_DURATION_MILLISECONDS, TCP_FLAGS,
           SRC_TO_DST_AVG_THROUGHPUT, packet-size buckets) make this flow
           suspicious. Reference the actual numbers (2-3 sentences).
        2. How the Suricata rule corroborates the ML classification (1-2 sentences).
        3. What the attacker is likely trying to achieve (1 sentence).
        4. Recommended response actions for the analyst (1-2 sentences).
    """).strip()


# ─────────────────────────────────────────────────────────────────────────────
# 6.  CSV LOADER  (NF-UNSW-NB15-v2)
# ─────────────────────────────────────────────────────────────────────────────

# Default Suricata rules mapped to known attack labels in the dataset.
# When loading from CSV we don't have a real IDS alert, so we synthesise one
# from this lookup table.
LABEL_TO_RULE: dict[str, tuple[str, str, str]] = {
    # label -> (severity, rule_msg, rule_full)
    "Exploits": (
        "critical",
        "ET EXPLOIT Generic Web Exploit Attempt",
        'alert http any any -> any any (msg:"ET EXPLOIT Generic Exploit"; content:"/../"; classtype:web-application-attack; sid:9000001; rev:1;)',
    ),
    "DoS": (
        "critical",
        "ET DOS High-Volume Flood Attack",
        'alert tcp any any -> any any (msg:"ET DOS Flood"; flags:S; threshold: type both, track by_src, count 1000, seconds 5; classtype:denial-of-service; sid:9000002; rev:1;)',
    ),
    "Reconnaissance": (
        "high",
        "ET SCAN Port/Host Scan Detected",
        'alert tcp any any -> any any (msg:"ET SCAN Port Scan"; flags:S; threshold: type both, track by_src, count 30, seconds 60; classtype:network-scan; sid:9000003; rev:1;)',
    ),
    "Fuzzers": (
        "high",
        "ET FUZZ Anomalous Application Layer Fuzzing",
        'alert tcp any any -> any any (msg:"ET FUZZ Application Fuzzer"; dsize:>1024; threshold: type both, track by_src, count 20, seconds 10; classtype:protocol-command-decode; sid:9000004; rev:1;)',
    ),
    "Analysis": (
        "medium",
        "ET ANALYSIS Suspicious Analytical Probe",
        'alert tcp any any -> any any (msg:"ET ANALYSIS Probe"; flags:S; threshold: type both, track by_src, count 10, seconds 60; classtype:network-scan; sid:9000005; rev:1;)',
    ),
    "Backdoor": (
        "high",
        "ET MALWARE Backdoor C2 Communication",
        'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Backdoor Beacon"; flow:to_server,established; classtype:trojan-activity; sid:9000006; rev:1;)',
    ),
    "Generic": (
        "medium",
        "ET GENERIC Unclassified Malicious Traffic",
        'alert tcp any any -> any any (msg:"ET GENERIC Malicious Traffic"; classtype:misc-attack; sid:9000007; rev:1;)',
    ),
    "Shellcode": (
        "critical",
        "ET SHELLCODE Binary Shellcode in Network Payload",
        'alert tcp any any -> any any (msg:"ET SHELLCODE Shellcode Detected"; content:"|90 90 90|"; classtype:shellcode-detect; sid:9000008; rev:1;)',
    ),
    "Worms": (
        "high",
        "ET MALWARE Worm Lateral Movement Detected",
        'alert tcp $HOME_NET any -> $HOME_NET any (msg:"ET MALWARE Worm Spreading"; flags:S; threshold: type both, track by_src, count 50, seconds 10; classtype:trojan-activity; sid:9000009; rev:1;)',
    ),
    "Benign": (
        "low",
        "No rule triggered – flow classified as benign",
        "",
    ),
}


def load_csv_flows(csv_path: str, attack_filter: Optional[str] = None,
                   n: int = 3) -> list[tuple[SuricataAlert, dict]]:
    """
    Load rows from NF-UNSW-NB15-v2.csv.
    Returns a list of (SuricataAlert, flow_dict) pairs ready for Case 2.
    """
    df = pd.read_csv(csv_path)

    # Normalise column names (strip spaces)
    df.columns = df.columns.str.strip()

    if attack_filter:
        df = df[df["Label"].str.strip() == attack_filter]
        if df.empty:
            print(f"[WARN] No rows found with Label='{attack_filter}'. "
                  f"Available labels: {df['Label'].unique().tolist()}")
            return []

    # Only take attack rows (Attack==1) unless filter explicitly includes benign
    if not attack_filter or attack_filter.lower() != "benign":
        df = df[df["Attack"] == 1]

    df = df.head(n)
    results = []
    for idx, row in df.iterrows():
        label = str(row.get("Label", "Generic")).strip()
        sev, rmsg, rfull = LABEL_TO_RULE.get(label, LABEL_TO_RULE["Generic"])
        alert = SuricataAlert(
            alert_id=f"CSV-{idx:04d}",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_ip=str(row.get("IPV4_SRC_ADDR", "0.0.0.0")),
            dst_ip=str(row.get("IPV4_DST_ADDR", "0.0.0.0")),
            dst_port=int(row.get("L4_DST_PORT", 0)),
            protocol="TCP" if int(row.get("PROTOCOL", 6)) == 6 else
                     "UDP" if int(row.get("PROTOCOL", 17)) == 17 else
                     str(row.get("PROTOCOL", "?")),
            severity=sev,
            attack_type=label,
            rule_msg=rmsg,
            rule_full=rfull,
        )
        results.append((alert, row.to_dict()))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 7.  EXPLAINER  –  the main engine
# ─────────────────────────────────────────────────────────────────────────────

class ThreatExplainer:
    def __init__(self, llm: LLMClient):
        self.llm = llm

    def explain_case1(self, alert: SuricataAlert) -> ExplanationResult:
        prompt = build_case1_prompt(alert)
        print(f"\n  [SYSTEM PROMPT]:\n{SYSTEM_PROMPT}")
        print(f"\n  [USER PROMPT]:\n{prompt}")
        print(f"\n  [CALLING LLM...]")
        explanation = self.llm.complete(SYSTEM_PROMPT, prompt,max_tokens=10)
        return ExplanationResult(
            case=1,
            event_id=alert.alert_id,
            attack_type=alert.attack_type,
            severity=alert.severity,
            src_ip=alert.src_ip,
            dst_ip=f"{alert.dst_ip}:{alert.dst_port}",
            rule_msg=alert.rule_msg,
            explanation=explanation,
        )

    def explain_case2(self, alert: SuricataAlert,
                      flow: dict) -> ExplanationResult:
        prompt = build_case2_prompt(alert, flow)
        print(f"\n  [SYSTEM PROMPT]:\n{SYSTEM_PROMPT}")
        print(f"\n  [USER PROMPT]:\n{prompt}")
        print(f"\n  [CALLING LLM...]")
        explanation = self.llm.complete(SYSTEM_PROMPT, prompt, max_tokens=100)
        return ExplanationResult(
            case=2,
            event_id=alert.alert_id,
            attack_type=alert.attack_type,
            severity=alert.severity,
            src_ip=alert.src_ip,
            dst_ip=f"{alert.dst_ip}:{alert.dst_port}",
            rule_msg=alert.rule_msg,
            explanation=explanation,
        )

    def run_case1_synthetic(self) -> list[ExplanationResult]:
        print("\n" + "="*70)
        print("CASE 1 – Suricata rule match + IP (no flow features)")
        print("="*70)
        results = []
        for alert in SYNTHETIC_ALERTS:
            print(f"\n[{alert.alert_id}] {alert.attack_type} | {alert.src_ip} → "
                  f"{alert.dst_ip}:{alert.dst_port} | {alert.severity.upper()}")
            print(f"  Rule : {alert.rule_msg}")
            print("  Calling LLM …", end="", flush=True)
            r = self.explain_case1(alert)
            print(" done.")
            print("EXPLANATION:\n",r.explanation)
            #print(f"\n  EXPLANATION:\n{textwrap.fill(r.explanation, 72, initial_indent='  ', subsequent_indent='  ')}")
            results.append(r)
        return results

    def run_case2_synthetic(self) -> list[ExplanationResult]:
        print("\n" + "="*70)
        print("CASE 2 – Rule + IP + NF-UNSW-NB15-v2 features (synthetic)")
        print("="*70)
        results = []
        for flow_dict in SYNTHETIC_FLOWS:
            label  = flow_dict.get("Label", "Unknown")
            src_ip = flow_dict.get("IPV4_SRC_ADDR", "?")
            dst_ip = flow_dict.get("IPV4_DST_ADDR", "?")
            dst_pt = flow_dict.get("L4_DST_PORT", 0)
            rmsg   = flow_dict.get("_rule_msg", "")
            rfull  = flow_dict.get("_rule_full", "")
            sev    = LABEL_TO_RULE.get(label, ("medium","",""))[0]

            alert = SuricataAlert(
                alert_id=f"SYN-F{SYNTHETIC_FLOWS.index(flow_dict)+1:02d}",
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                src_ip=src_ip, dst_ip=dst_ip, dst_port=int(dst_pt),
                protocol="TCP" if flow_dict.get("PROTOCOL")==6 else "UDP",
                severity=sev, attack_type=label,
                rule_msg=rmsg, rule_full=rfull,
            )
            print(f"\n[{alert.alert_id}] {label} | {src_ip} → {dst_ip}:{dst_pt} | {sev.upper()}")
            print(f"  Rule : {rmsg}")
            print("  Calling LLM …", end="", flush=True)
            r = self.explain_case2(alert, flow_dict)
            print(" done.")
            print(f"\n  EXPLANATION:\n{textwrap.fill(r.explanation, 72, initial_indent='  ', subsequent_indent='  ')}")
            results.append(r)
        return results

    def run_case2_csv(self, csv_path: str, attack_filter: Optional[str],
                      n: int) -> list[ExplanationResult]:
        print("\n" + "="*70)
        print(f"CASE 2 – CSV ({csv_path})"
              + (f" | filter: {attack_filter}" if attack_filter else "")
              + f" | n={n}")
        print("="*70)
        pairs = load_csv_flows(csv_path, attack_filter, n)
        if not pairs:
            print("[WARN] No records loaded from CSV.")
            return []
        results = []
        for alert, flow in pairs:
            print(f"\n[{alert.alert_id}] {alert.attack_type} | "
                  f"{alert.src_ip} → {alert.dst_ip}:{alert.dst_port} | {alert.severity.upper()}")
            print(f"  Rule : {alert.rule_msg}")
            print("  Calling LLM …", end="", flush=True)
            r = self.explain_case2(alert, flow)
            print(" done.")
            print(f"\n  EXPLANATION:\n{textwrap.fill(r.explanation, 72, initial_indent='  ', subsequent_indent='  ')}")
            results.append(r)
        return results


# ─────────────────────────────────────────────────────────────────────────────
# 8.  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Cyber Threat Explainer – LLM-powered natural language explanations"
    )
    p.add_argument("--csv",    type=str,  default=None,
                   help="Path to NF-UNSW-NB15-v2.csv (triggers CSV mode for Case 2)")
    p.add_argument("--attack", type=str,  default=None,
                   help="Filter CSV by attack label, e.g. DoS, Exploits, Worms")
    p.add_argument("--n",      type=int,  default=3,
                   help="Number of CSV rows to explain (default: 3)")
    p.add_argument("--case",   type=str,  default="all",
                   choices=["1","2","all"],
                   help="Which case to run: 1, 2, or all (default)")
    p.add_argument("--out",    type=str,  default=None,
                   help="Write results to a JSON file")
    return p.parse_args()


def main():
    args = parse_args()

    # Initialise LLM (will raise if SDK not installed / key wrong)
    try:
        llm = LLMClient()
    except Exception as e:
        print(f"[ERROR] Could not initialise LLM client: {e}")
        print("        Edit the LLMClient class at the top of this file and set your API key.")
        sys.exit(1)

    explainer = ThreatExplainer(llm)
    all_results: list[ExplanationResult] = []

    if args.case in ("1", "all"):
        all_results += explainer.run_case1_synthetic()

    if args.case in ("2", "all"):
        if args.csv:
            all_results += explainer.run_case2_csv(args.csv, args.attack, args.n)
        else:
            all_results += explainer.run_case2_synthetic()

    # Optional JSON output
    if args.out:
        with open(args.out, "w") as f:
            json.dump([asdict(r) for r in all_results], f, indent=2)
        print(f"\n[INFO] Results saved → {args.out}")

    print(f"\n[DONE] {len(all_results)} explanation(s) generated.")


if __name__ == "__main__":
    main()
