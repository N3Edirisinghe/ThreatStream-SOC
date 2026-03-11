#!/usr/bin/env python3
"""
Synthetic Log Generator — SOC Platform MVP
Generates realistic Windows Event Logs, Linux syslog, firewall, and web logs
as JSON Lines files. Plants known attack patterns for ground-truth evaluation.

Usage:
    python generate_synthetic_logs.py --count 10000 --out ./data/sample_logs/
    python generate_synthetic_logs.py --attack-only --out ./data/sample_logs/
"""
import argparse
import json
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ─── Configuration ────────────────────────────────────────────────────────────

USERS = [
    "jsmith", "alee", "mwilson", "rgarcia", "ptaylor",
    "cmartin", "lwhite", "bmoore", "djohnson", "kthomas",
    "svc_backup", "svc_monitoring", "svc_deploy",
]
WORKSTATIONS = [f"WS-{i:03d}" for i in range(1, 21)]
SERVERS = ["WIN-DC01", "WIN-DC02", "WIN-FS01", "WIN-SQL01", "WEB-PROD01"]
ALL_HOSTS = WORKSTATIONS + SERVERS

INTERNAL_IPS = [f"10.0.{random.randint(1,5)}.{random.randint(1,254)}" for _ in range(30)]
EXTERNAL_IPS_BENIGN = [
    "8.8.8.8", "1.1.1.1", "52.84.31.100", "172.217.6.142",
    "104.16.85.20", "151.101.64.81",
]
EXTERNAL_IPS_MALICIOUS = [
    "185.220.101.47", "194.165.16.11", "45.142.212.100",
    "91.109.190.7", "185.176.27.231", "195.78.54.169",
]

PROCESSES_NORMAL = [
    "explorer.exe", "svchost.exe", "taskmgr.exe", "notepad.exe",
    "chrome.exe", "outlook.exe", "teams.exe", "mstsc.exe",
]
PROCESSES_SUSPICIOUS = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
]


def ts_now(offset_minutes: int = 0) -> str:
    """Return ISO8601 UTC timestamp with optional minute offset."""
    t = datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def rand_ts(days_back: int = 7) -> str:
    """Return a random timestamp within the past N days."""
    delta = random.randint(0, days_back * 24 * 60)
    t = datetime.now(timezone.utc) - timedelta(minutes=delta)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── Normal Event Generators ──────────────────────────────────────────────────

def gen_windows_logon_success() -> dict:
    return {
        "source_type": "windows_event",
        "host": random.choice(ALL_HOSTS),
        "timestamp": rand_ts(7),
        "winlog_event_id": 4624,
        "message": "An account was successfully logged on.",
        "user": random.choice(USERS),
        "logon_type": random.choice([2, 3, 10]),
        "source_ip": random.choice(INTERNAL_IPS),
        "auth_package": random.choice(["Kerberos", "NTLM"]),
        "_label": "normal",
    }


def gen_windows_logon_failure() -> dict:
    return {
        "source_type": "windows_event",
        "host": random.choice(ALL_HOSTS),
        "timestamp": rand_ts(7),
        "winlog_event_id": 4625,
        "message": "An account failed to log on.",
        "user": random.choice(USERS),
        "logon_type": 3,
        "source_ip": random.choice(INTERNAL_IPS + EXTERNAL_IPS_BENIGN),
        "failure_reason": "Unknown user name or bad password",
        "_label": "normal",
    }


def gen_process_creation() -> dict:
    return {
        "source_type": "windows_event",
        "host": random.choice(WORKSTATIONS),
        "timestamp": rand_ts(7),
        "winlog_event_id": 4688,
        "message": "A new process has been created.",
        "user": random.choice(USERS),
        "process_name": random.choice(PROCESSES_NORMAL),
        "parent_process": "explorer.exe",
        "command_line": random.choice(PROCESSES_NORMAL),
        "_label": "normal",
    }


def gen_linux_syslog() -> dict:
    facilities = ["auth", "daemon", "kern", "user", "syslog"]
    messages = [
        "pam_unix(sshd:auth): authentication failure",
        "Accepted publickey for ubuntu from 10.0.1.5 port 52341",
        "Started Session 42 of user deploy.",
        "systemd[1]: Started nginx.service",
        "kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156",
    ]
    return {
        "source_type": "linux_syslog",
        "host": f"linux-{random.randint(1,5):02d}",
        "timestamp": rand_ts(7),
        "facility": random.choice(facilities),
        "severity": random.choice(["info", "notice", "warning"]),
        "message": random.choice(messages),
        "user": random.choice(USERS + [None]),
        "_label": "normal",
    }


def gen_firewall_log() -> dict:
    return {
        "source_type": "firewall_pfsense",
        "host": "FIREWALL-01",
        "timestamp": rand_ts(7),
        "action": random.choice(["pass", "pass", "pass", "block"]),
        "direction": random.choice(["in", "out"]),
        "src_ip": random.choice(INTERNAL_IPS + EXTERNAL_IPS_BENIGN),
        "dst_ip": random.choice(INTERNAL_IPS + EXTERNAL_IPS_BENIGN),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 8080, 22, 3389, 445, 53]),
        "protocol": random.choice(["TCP", "UDP"]),
        "bytes": random.randint(64, 65535),
        "_label": "normal",
    }


def gen_nginx_log() -> dict:
    paths = ["/", "/login", "/api/v1/status", "/dashboard", "/static/app.js", "/favicon.ico"]
    methods = ["GET", "GET", "GET", "POST"]
    statuses = [200, 200, 200, 304, 404, 301]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "curl/7.68.0",
        "python-httpx/0.23.0",
    ]
    return {
        "source_type": "nginx_access",
        "host": "WEB-PROD01",
        "timestamp": rand_ts(7),
        "src_ip": random.choice(INTERNAL_IPS + EXTERNAL_IPS_BENIGN),
        "method": random.choice(methods),
        "path": random.choice(paths),
        "status_code": random.choice(statuses),
        "bytes_sent": random.randint(200, 50000),
        "user_agent": random.choice(user_agents),
        "request_time_ms": random.randint(5, 2000),
        "_label": "normal",
    }


# ─── ATTACK Pattern Generators ────────────────────────────────────────────────

def plant_brute_force(base_ts_offset: int = 0) -> list:
    """
    det-001: 6+ auth failures from same IP to same user within 60s.
    Returns list of event dicts (all timestamped within same minute).
    """
    attacker_ip = random.choice(EXTERNAL_IPS_MALICIOUS)
    victim_user = random.choice(USERS[:5])
    victim_host = random.choice(SERVERS)
    events = []
    for i in range(random.randint(6, 12)):
        t = datetime.now(timezone.utc) - timedelta(minutes=base_ts_offset) + timedelta(seconds=i * 8)
        events.append({
            "source_type": "windows_event",
            "host": victim_host,
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "winlog_event_id": 4625,
            "message": "An account failed to log on.",
            "user": victim_user,
            "logon_type": 3,
            "source_ip": attacker_ip,
            "failure_reason": "Unknown user name or bad password",
            "_label": "attack",
            "_attack_type": "brute_force",
            "_attack_id": str(uuid.uuid4()),
        })
    return events


def plant_encoded_powershell(base_ts_offset: int = 0) -> list:
    """
    det-004: PowerShell with -EncodedCommand flag.
    A realistic base64-encoded payload (harmless: just echo hello).
    """
    encoded = "ZQBjAGgAbwAgAGgAZQBsAGwAbwA="  # echo hello in UTF-16LE base64
    t = datetime.now(timezone.utc) - timedelta(minutes=base_ts_offset)
    return [{
        "source_type": "windows_event",
        "host": random.choice(WORKSTATIONS),
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "winlog_event_id": 4688,
        "message": "A new process has been created.",
        "user": random.choice(USERS[:5]),
        "process_name": "powershell.exe",
        "parent_process": "cmd.exe",
        "command_line": f"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
        "_label": "attack",
        "_attack_type": "encoded_powershell",
        "_attack_id": str(uuid.uuid4()),
    }]


def plant_registry_persistence(base_ts_offset: int = 0) -> list:
    """det-006: Registry Run key write."""
    t = datetime.now(timezone.utc) - timedelta(minutes=base_ts_offset)
    return [{
        "source_type": "windows_event",
        "host": random.choice(WORKSTATIONS),
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "winlog_event_id": 4657,
        "message": "A registry value was modified.",
        "user": random.choice(USERS[:5]),
        "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "registry_value_name": "WindowsUpdater",
        "registry_value_data": "C:\\Users\\Public\\updater.exe",
        "process_name": "powershell.exe",
        "_label": "attack",
        "_attack_type": "registry_persistence",
        "_attack_id": str(uuid.uuid4()),
    }]


def plant_lateral_movement_pth(base_ts_offset: int = 0) -> list:
    """
    det-010: Pass-the-Hash — NTLM logon type 3 to 3+ unique hosts within 5 min.
    """
    attacker_user = random.choice(USERS[:5])
    events = []
    for i in range(random.randint(3, 5)):
        t = datetime.now(timezone.utc) - timedelta(minutes=base_ts_offset) + timedelta(seconds=i * 45)
        events.append({
            "source_type": "windows_event",
            "host": SERVERS[i % len(SERVERS)],
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "winlog_event_id": 4624,
            "message": "An account was successfully logged on.",
            "user": attacker_user,
            "logon_type": 3,
            "auth_package": "NTLM",
            "source_ip": random.choice(INTERNAL_IPS),
            "_label": "attack",
            "_attack_type": "lateral_movement_pth",
            "_attack_id": str(uuid.uuid4()),
        })
    return events


def plant_c2_beaconing(base_ts_offset: int = 0) -> list:
    """
    det-009: Periodic outbound connections to same C2 IP, low jitter.
    """
    src_host = random.choice(WORKSTATIONS)
    c2_ip = random.choice(EXTERNAL_IPS_MALICIOUS)
    events = []
    for i in range(random.randint(8, 12)):
        jitter_secs = random.randint(-4, 4)  # <15% jitter
        t = (datetime.now(timezone.utc)
             - timedelta(minutes=base_ts_offset)
             + timedelta(seconds=i * 30 + jitter_secs))
        events.append({
            "source_type": "firewall_pfsense",
            "host": "FIREWALL-01",
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "action": "pass",
            "direction": "out",
            "src_ip": random.choice(INTERNAL_IPS),
            "dst_ip": c2_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": 4444,
            "protocol": "TCP",
            "bytes": random.randint(200, 800),
            "_label": "attack",
            "_attack_type": "c2_beaconing",
            "_attack_id": str(uuid.uuid4()),
        })
    return events


def plant_suspicious_outbound(base_ts_offset: int = 0) -> list:
    """det-007: Large outbound to high-risk country IP."""
    t = datetime.now(timezone.utc) - timedelta(minutes=base_ts_offset)
    return [{
        "source_type": "firewall_pfsense",
        "host": "FIREWALL-01",
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "pass",
        "direction": "out",
        "src_ip": random.choice(INTERNAL_IPS),
        "dst_ip": "185.220.101.47",
        "dst_geo_country": "RU",
        "src_port": random.randint(49152, 65535),
        "dst_port": 443,
        "protocol": "TCP",
        "bytes": random.randint(100000, 5000000),
        "_label": "attack",
        "_attack_type": "suspicious_outbound",
        "_attack_id": str(uuid.uuid4()),
    }]


# ─── Main Generator ───────────────────────────────────────────────────────────

NORMAL_GENERATORS = [
    (gen_windows_logon_success, 0.30),
    (gen_windows_logon_failure, 0.10),
    (gen_process_creation,      0.20),
    (gen_linux_syslog,          0.15),
    (gen_firewall_log,          0.15),
    (gen_nginx_log,             0.10),
]

ATTACK_SEQUENCES = [
    plant_brute_force,
    plant_encoded_powershell,
    plant_registry_persistence,
    plant_lateral_movement_pth,
    plant_c2_beaconing,
    plant_suspicious_outbound,
]


def generate_normal_event() -> dict:
    """Pick a normal generator by weighted random selection."""
    generators, weights = zip(*NORMAL_GENERATORS)
    chosen = random.choices(generators, weights=weights, k=1)[0]
    return chosen()


def main():
    parser = argparse.ArgumentParser(description="SOC Synthetic Log Generator")
    parser.add_argument("--count",       type=int, default=10000,       help="Normal event count")
    parser.add_argument("--attacks",     type=int, default=50,          help="Number of attack sequences to plant")
    parser.add_argument("--out",         type=str, default="./data/sample_logs/", help="Output directory")
    parser.add_argument("--attack-only", action="store_true",           help="Generate only attack events")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_events = []

    # ── Generate normal events ──────────────────────────────────────────────
    if not args.attack_only:
        print(f"[+] Generating {args.count:,} normal events …")
        for _ in range(args.count):
            all_events.append(generate_normal_event())

    # ── Plant attack sequences ──────────────────────────────────────────────
    print(f"[+] Planting {args.attacks} attack sequences …")
    attack_events = []
    for i in range(args.attacks):
        attacker_fn = random.choice(ATTACK_SEQUENCES)
        # Scatter across past 7 days
        offset = random.randint(0, 7 * 24 * 60)
        batch = attacker_fn(base_ts_offset=offset)
        attack_events.extend(batch)
        if (i + 1) % 10 == 0:
            print(f"    … {i+1}/{args.attacks} sequences planted")

    all_events.extend(attack_events)

    # ── Shuffle and sort by timestamp ──────────────────────────────────────
    random.shuffle(all_events)
    all_events.sort(key=lambda e: e.get("timestamp", ""))

    # ── Write output files ─────────────────────────────────────────────────
    # All events (mixed)
    mixed_path = out_dir / "synthetic_mixed.jsonl"
    with open(mixed_path, "w", encoding="utf-8") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")
    print(f"[+] Written {len(all_events):,} events → {mixed_path}")

    # Attack-only (ground truth labels)
    attack_path = out_dir / "synthetic_attacks_ground_truth.jsonl"
    with open(attack_path, "w", encoding="utf-8") as f:
        for event in attack_events:
            f.write(json.dumps(event) + "\n")
    print(f"[+] Written {len(attack_events):,} attack events → {attack_path}")

    # Summary
    attack_types = {}
    for e in attack_events:
        at = e.get("_attack_type", "unknown")
        attack_types[at] = attack_types.get(at, 0) + 1

    print("\n──── Generation Summary ────")
    print(f"  Total events   : {len(all_events):,}")
    print(f"  Normal events  : {len(all_events) - len(attack_events):,}")
    print(f"  Attack events  : {len(attack_events):,}")
    print("  Attack breakdown:")
    for atype, cnt in sorted(attack_types.items()):
        print(f"    {atype:<30} {cnt:>4} events")
    print("────────────────────────────")


if __name__ == "__main__":
    main()
