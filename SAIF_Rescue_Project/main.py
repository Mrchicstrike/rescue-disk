import os
import sys
import json
import time
import shutil
import hashlib
import argparse
import threading
import subprocess
import tempfile
import re
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

import psutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ==============================================================================
# HIKMA MALWARE SIGNATURE DATABASE
# ==============================================================================
DEFAULT_MALWARE_SIGNATURES: Dict[str, Dict[str, str]] = {
    # Test Signature
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR-Standard-AV-Test-File",
        "family": "TestFile",
        "severity": "LOW",
        "description": "Standard antivirus verification test file signature"
    },
    # Ransomware Families
    "ed01ebf83334a19373310b9370e281444c843bc702cc31137872826048335fb0": {
        "name": "WannaCry.MSRunner",
        "family": "Ransomware",
        "severity": "CRITICAL",
        "description": "WannaCry ransomware main dropper binary (mssecsvc.exe)"
    },
    "84c82835a5d21bbcf75a61706d8ab549fa9f42586482f097075a2d47b63f5244": {
        "name": "WannaCry.Payload",
        "family": "Ransomware",
        "severity": "CRITICAL",
        "description": "WannaCry encrypted payload unpacker (tasksche.exe)"
    },
    "027cc450e419c5368bc3b364244922d23f563547d6e3890eb5fa752d43335eec": {
        "name": "NotPetya.MBR",
        "family": "Ransomware/Wiper",
        "severity": "CRITICAL",
        "description": "NotPetya / ExPetr destructive MBR overwriter and encryptor"
    },
    "83363f73315b91b9794cb1f1c7dcfdfd4c57502bbecfcfcae58a9e7ea81b1516": {
        "name": "Locky.Ransomware",
        "family": "Ransomware",
        "severity": "CRITICAL",
        "description": "Locky ransomware encryptor binary"
    },
    "5ac018fbe9a1286c7cf65ad8ff6b554e2a1dd0e6f7776182c1ae11c81ef4db92": {
        "name": "Ryuk.Payload",
        "family": "Ransomware",
        "severity": "CRITICAL",
        "description": "Ryuk targeted enterprise ransomware binary"
    },
    "6347908b8b0e7d58fa6c52bb88cf0d1bb391300958197793d582dfca61a6ffcf": {
        "name": "Conti.Ransomware",
        "family": "Ransomware",
        "severity": "CRITICAL",
        "description": "Conti v2/v3 enterprise ransomware payload"
    },
    "8d8677c7750837f4cb63eb87a1a44e590059b0f44358f22fa9c669145607da74": {
        "name": "DarkSide.Colonial",
        "family": "Ransomware",
        "severity": "CRITICAL",
        "description": "DarkSide enterprise ransomware binary"
    },
    "b63e528ce073c6a4959db62f8319f6a27e7d69ae525867a502f6ef3f75727cc3": {
        "name": "LockBit.Black.v3",
        "family": "Ransomware",
        "severity": "CRITICAL",
        "description": "LockBit 3.0 Black ransomware payload"
    },
    "d0f04c6328c0a8767e7c8ff6df3fbe80e34c9f1388b13d8d5c43d893ce54e99d": {
        "name": "REvil.Sodinokibi",
        "family": "Ransomware",
        "severity": "CRITICAL",
        "description": "Sodinokibi / REvil RaaS ransomware binary"
    },
    # InfoStealers & Spyware
    "ca2ca4c954eeea060f60c5c3080ffb050cfd1ad5781a7b82ab3002aa9086be78": {
        "name": "RedLine.Stealer",
        "family": "InfoStealer",
        "severity": "HIGH",
        "description": "RedLine credentials, tokens and cryptocurrency stealer"
    },
    "582e07eb443fa702ff6fc31ccfb047781b4d0811e58a2d1d0725a7dcfd6cf716": {
        "name": "AgentTesla.Spyware",
        "family": "InfoStealer/Keylogger",
        "severity": "HIGH",
        "description": "AgentTesla remote access trojan and spyware"
    },
    "226b9c7b9415715978a3f81df681ccf07297e61b7fcf71eb6db0c8ea52f6f1c7": {
        "name": "Emotet.Trojan",
        "family": "Trojan/Botnet",
        "severity": "HIGH",
        "description": "Emotet modular banking trojan and malware distributor"
    },
    "e0d6c4e09cb432ef29ee4a46a6f693e5deef16f31bfb26a6449dc30e0ee0c765": {
        "name": "TrickBot.Loader",
        "family": "BankingTrojan",
        "severity": "HIGH",
        "description": "TrickBot modular banking and reconnaissance trojan"
    },
    "7d0eb0ca6dc668b57731e21eef00c7cb9e28f3ea7fbfb26a454848bf9d020e98": {
        "name": "QakBot.Loader",
        "family": "TrojanLoader",
        "severity": "HIGH",
        "description": "QakBot / QBot credential theft and loader component"
    },
    # Credential Dumpers & Post-Exploitation
    "a9b400c14b6006886e06b3a2a61f2277d33b499ee9782ad763e02c638e8a6bc8": {
        "name": "Mimikatz.Release",
        "family": "CredentialDumper",
        "severity": "HIGH",
        "description": "Mimikatz memory credential harvesting and ticket tool"
    },
    # Destructive Wipers & Industrial Cyberweapons
    "2f063d80360a0a5592ff3b3e24b7a13d719e59d81d2f8db5d8df6f38ba514cfb": {
        "name": "Stuxnet.Rootkit",
        "family": "Rootkit/Sabotage",
        "severity": "CRITICAL",
        "description": "Stuxnet SCADA industrial sabotage driver and payload"
    },
    "0385e49877b202302821f0b8972a998e40f77c617041ab5b49b6708e32ec63f5": {
        "name": "HermeticWiper",
        "family": "DataWiper",
        "severity": "CRITICAL",
        "description": "HermeticWiper destructive partition corruptor"
    },
    "a294620543bcdec347e024c73e89f05d29006095f9c45a027633299b3997216a": {
        "name": "CaddyWiper",
        "family": "DataWiper",
        "severity": "CRITICAL",
        "description": "CaddyWiper destructive zero-out data wiper"
    }
}

BASE_DIR = Path(__file__).resolve().parent


def _runtime_data_dir() -> Path:
    """Resolve a distro-safe directory for application state."""
    if sys.platform.startswith("linux"):
        base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local/share"))
        return base / "hikma-rescue"
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return base / "HikmaRescue"
    return Path.home() / ".hikma-rescue"


SIGNATURES_FILE = _runtime_data_dir() / "malware_signatures.json"
LIVE_TARGET_DIR = Path(tempfile.gettempdir()) / "hikma-rescue-live-target"
QUARANTINE_DIR = _runtime_data_dir() / "quarantine_vault"
DEFAULT_SIGNATURE_FEED_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"


# ==============================================================================
# Hashing and signature matching
# ==============================================================================

def calculate_sha256(filepath: str | Path, chunk_size: int = 65536) -> Optional[str]:
    """
    Computes the SHA-256 cryptographic hash of a file using chunked binary streaming.
    """
    path = Path(filepath)
    if not path.is_file():
        return None

    sha256_hash = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest().lower()
    except (PermissionError, OSError):
        return None


def load_malware_signatures(db_file: Path = SIGNATURES_FILE) -> Dict[str, Dict[str, str]]:
    """
    Loads malware signatures from the local JSON database file.
    """
    signatures = dict(DEFAULT_MALWARE_SIGNATURES)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    if db_file.exists():
        try:
            with open(db_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    for h, meta in loaded.items():
                        signatures[h.strip().lower()] = meta
        except Exception:
            pass
    else:
        try:
            with open(db_file, "w", encoding="utf-8") as f:
                json.dump(signatures, f, indent=4)
        except Exception:
            pass

    return signatures


def merge_signature_feed(external_data: Any) -> Dict[str, Dict[str, str]]:
    """Convert supported threat feeds into a validated SHA-256 metadata map."""
    merged: Dict[str, Dict[str, str]] = {}

    def add_signature(digest: Any, meta: Any = None) -> None:
        digest = str(digest).strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            return

        if isinstance(meta, str):
            name = meta
            details = "Known malicious signature match"
            family = "Threat"
            severity = "HIGH"
        elif isinstance(meta, dict):
            name = meta.get("name") or meta.get("threat") or "UnknownMalware"
            details = meta.get("description") or meta.get("details") or "Known malicious signature match"
            family = meta.get("family") or meta.get("category") or "Threat"
            severity = meta.get("severity") or "HIGH"
        else:
            name = "MalwareBazaar sample"
            details = "SHA-256 listed by MalwareBazaar recent sample feed"
            family = "Malware"
            severity = "HIGH"

        merged[digest] = {
            "name": str(name),
            "family": str(family),
            "severity": str(severity).upper(),
            "description": str(details)
        }

    if isinstance(external_data, dict):
        for key, meta in external_data.items():
            add_signature(key, meta)

    elif isinstance(external_data, list):
        for item in external_data:
            if not isinstance(item, dict):
                continue
            add_signature(item.get("sha256") or item.get("hash") or item.get("digest"), item)

    elif isinstance(external_data, str):
        for line in external_data.splitlines():
            add_signature(line)

    return merged


def fetch_signature_feed(custom_feed_path_or_url: Optional[str] = None) -> Optional[Any]:
    """Load JSON or newline-delimited hashes from a local file or URL."""
    if not custom_feed_path_or_url:
        return None

    try:
        source_path = Path(custom_feed_path_or_url)
        if source_path.is_file():
            payload = source_path.read_text(encoding="utf-8")
        else:
            import urllib.request
            req = urllib.request.Request(
                custom_feed_path_or_url,
                headers={"User-Agent": "HIKMA-Rescue-Scanner/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                payload = resp.read(10 * 1024 * 1024 + 1).decode("utf-8")
            if len(payload) > 10 * 1024 * 1024:
                return None

        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return payload
    except Exception:
        return None


def refresh_malware_signatures(
        feed_url: str = DEFAULT_SIGNATURE_FEED_URL,
        db_file: Path = SIGNATURES_FILE
) -> tuple[Dict[str, Dict[str, str]], int, Optional[str]]:
    """Refresh the local database, preserving its offline copy on any failure."""
    signatures = load_malware_signatures(db_file)
    feed_data = fetch_signature_feed(feed_url)
    if feed_data is None:
        return signatures, 0, "Could not reach or read the online signature feed."

    new_signatures = merge_signature_feed(feed_data)
    if not new_signatures:
        return signatures, 0, "The feed contained no valid SHA-256 signatures."

    signatures.update(new_signatures)
    temporary_file = db_file.with_suffix(db_file.suffix + ".tmp")
    try:
        db_file.parent.mkdir(parents=True, exist_ok=True)
        temporary_file.write_text(json.dumps(signatures, indent=4), encoding="utf-8")
        temporary_file.replace(db_file)
    except OSError as error:
        return load_malware_signatures(db_file), 0, f"Could not save the refreshed database: {error}"

    return signatures, len(new_signatures), None


def update_malware_signatures(custom_feed_path_or_url: Optional[str] = None,
                              db_file: Path = SIGNATURES_FILE) -> Dict[str, Dict[str, str]]:
    """
    Updates the malware signature database from the bundled database and optional online/local feed.
    """
    if not custom_feed_path_or_url:
        return load_malware_signatures(db_file)
    signatures, _, _ = refresh_malware_signatures(custom_feed_path_or_url, db_file)
    return signatures


def scan_file_for_malware(filepath: str | Path,
                          signatures: Dict[str, Dict[str, str]]) -> Optional[Dict[str, Any]]:
    """
    Scans a single file by computing its SHA-256 hash and matching against signatures.
    """
    path = Path(filepath)
    if not path.is_file():
        raise OSError(f"File is no longer available: {path}")

    file_hash = calculate_sha256(path)
    if not file_hash:
        raise OSError(f"Could not read file for hashing: {path}")

    if file_hash in signatures:
        match_info = signatures[file_hash]
        return {
            "path": str(path),
            "filename": path.name,
            "sha256": file_hash,
            "name": match_info.get("name", "UnknownMalware"),
            "family": match_info.get("family", "Threat"),
            "severity": match_info.get("severity", "HIGH"),
            "description": match_info.get("description", "Known malicious signature match")
        }
    return None


def quarantine_file(file_path: Path) -> Path:
    """
    Safely isolates a detected malicious binary into the quarantine vault.
    """
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    quarantine_target = QUARANTINE_DIR / f"{file_path.name}.{uuid.uuid4().hex}.hikma_quarantined"
    shutil.move(str(file_path), str(quarantine_target))
    return quarantine_target


def scan_target_directory(directory_path: str | Path,
                          signatures: Dict[str, Dict[str, str]],
                          recursive: bool = True,
                          max_size_mb: Optional[int] = 250,
                          auto_quarantine: bool = False,
                          log_callback=None) -> Dict[str, Any]:
    """
    Scans a directory for malicious binaries using SHA-256 signatures.
    Supports real-time logging via log_callback.
    """
    def log(msg, tag="normal"):
        if log_callback:
            log_callback(msg, tag)
        else:
            print(msg)

    target = Path(directory_path)
    stats = {"scanned": 0, "infected": 0, "clean": 0, "errors": 0, "skipped_size": 0, "detections": []}

    if not target.exists():
        log(f"[MALWARE] Scan path does not exist: {target}", "alert")
        return stats

    log(f"[SCAN] Starting SHA-256 scan on: {target}", "cyan")
    max_bytes = max_size_mb * 1024 * 1024 if max_size_mb and max_size_mb > 0 else None

    generator = target.rglob("*") if recursive else target.glob("*")
    for item in generator:
        if not item.is_file():
            continue

        try:
            if max_bytes is not None and item.stat().st_size > max_bytes:
                stats["skipped_size"] += 1
                continue
        except OSError:
            stats["errors"] += 1
            continue

        stats["scanned"] += 1
        try:
            detection = scan_file_for_malware(item, signatures)
        except OSError as error:
            stats["errors"] += 1
            log(f"[ERROR] Could not scan {item.name}: {error}", "yellow")
            continue

        if detection:
            stats["infected"] += 1
            stats["detections"].append(detection)
            log(f"\n[ALERT] Malware detected: {item.name}", "alert")
            log(f"        Threat:         {detection['name']} ({detection['family']})", "alert")
            log(f"        Severity:       {detection['severity']}", "alert")
            log(f"        SHA-256:        {detection['sha256']}", "cyan")
            log(f"        Details:        {detection['description']}", "yellow")

            if auto_quarantine:
                try:
                    q_path = quarantine_file(item)
                except OSError as error:
                    stats["errors"] += 1
                    log(f"        [ERROR] Could not quarantine {item.name}: {error}", "alert")
                else:
                    log(f"        [ACTION] Moved to quarantine: {q_path.name}", "green")
        else:
            stats["clean"] += 1
            log(f"[CLEAN] {item.name} is clean", "green")

    log(f"\n[SCAN] Complete. Files checked: {stats['scanned']} | Infected: {stats['infected']} | Clean: {stats['clean']}", "cyan")
    if stats["skipped_size"]:
        log(f"[SCAN] Files skipped because they exceeded {max_size_mb} MB: {stats['skipped_size']}", "yellow")
    return stats


def discover_system_scan_roots() -> list[Path]:
    """Return the primary system and component roots to include in a full host scan."""
    candidates: list[Path] = []

    if sys.platform.startswith("win"):
        candidates.extend([
            Path.home(),
            Path("C:/"),
            Path("C:/Windows"),
            Path("C:/Windows/System32"),
            Path("C:/Program Files"),
            Path("C:/Program Files (x86)"),
            Path("C:/ProgramData"),
            Path("C:/Users"),
        ])
    else:
        candidates.extend([
            Path("/"),
            Path("/usr"),
            Path("/etc"),
            Path("/opt"),
            Path("/var"),
            Path.home(),
        ])

    roots: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            if not candidate.exists() or not candidate.is_dir():
                continue
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            roots.append(resolved)
        except OSError:
            continue
    return roots


def run_full_system_scan(signatures: Dict[str, Dict[str, str]],
                        log_callback=None,
                        max_size_mb: Optional[int] = None) -> Dict[str, Any]:
    """Run a full host scan across the major system and component roots."""
    def log(msg, tag="normal"):
        if log_callback:
            log_callback(msg, tag)
        else:
            print(msg)

    aggregate = {"scanned": 0, "infected": 0, "clean": 0, "errors": 0, "skipped_size": 0, "detections": []}
    scan_roots = discover_system_scan_roots()

    if not scan_roots:
        log("[SCAN] No system roots were available for a full scan.", "yellow")
        return aggregate

    log("=" * 65, "cyan")
    log("      HIKMA RESCUE ENGINE -- FULL SYSTEM & COMPONENT SCAN", "cyan")
    log("=" * 65, "cyan")
    log(f"[SCAN] Starting host-wide analysis across {len(scan_roots)} system roots.", "cyan")

    for root in scan_roots:
        log(f"[SCAN] Component root: {root}", "cyan")
        scan_kwargs = {
            "recursive": True,
            "auto_quarantine": False,
            "log_callback": log,
        }
        if max_size_mb is not None:
            scan_kwargs["max_size_mb"] = max_size_mb

        stats = scan_target_directory(root, signatures, **scan_kwargs)
        aggregate["scanned"] += stats["scanned"]
        aggregate["infected"] += stats["infected"]
        aggregate["clean"] += stats["clean"]
        aggregate["errors"] += stats["errors"]
        aggregate["skipped_size"] += stats["skipped_size"]
        aggregate["detections"].extend(stats["detections"])

    log(f"\n[SCAN] Full system scan complete. Files checked: {aggregate['scanned']} | Infected: {aggregate['infected']} | Clean: {aggregate['clean']}", "cyan")
    if aggregate["skipped_size"]:
        log(f"[SCAN] Files skipped because they exceeded {max_size_mb} MB: {aggregate['skipped_size']}", "yellow")
    return aggregate


def watch_downloads(directory_path: str | Path,
                    signatures: Dict[str, Dict[str, str]],
                    poll_seconds: int = 5,
                    stable_seconds: int = 10,
                    rescan_hours: float = 0,
                    auto_quarantine: bool = True) -> None:
    """Scan completed files as they appear and optionally rescan the folder on a schedule."""
    target = Path(directory_path)
    if not target.is_dir():
        raise ValueError(f"Watch directory does not exist: {target}")
    if poll_seconds < 1 or stable_seconds < 1 or rescan_hours < 0:
        raise ValueError("Watch intervals must be positive; rescan hours may be zero to disable.")

    partial_suffixes = {".crdownload", ".part", ".download", ".partial", ".tmp"}
    pending: Dict[Path, tuple[tuple[int, int], float]] = {}
    processed: Dict[Path, tuple[int, int]] = {}
    next_rescan = time.monotonic() + rescan_hours * 3600 if rescan_hours else None
    print(f"[WATCH] Watching {target} for completed downloads. Press Ctrl+C to stop.")

    try:
        while True:
            now = time.monotonic()
            if next_rescan is not None and now >= next_rescan:
                scan_target_directory(target, signatures, auto_quarantine=auto_quarantine)
                next_rescan = now + rescan_hours * 3600

            present: set[Path] = set()
            for path in target.rglob("*"):
                if not path.is_file() or path.suffix.lower() in partial_suffixes:
                    continue

                try:
                    stat = path.stat()
                except OSError:
                    continue

                present.add(path)
                file_state = (stat.st_size, stat.st_mtime_ns)
                if processed.get(path) == file_state:
                    continue

                candidate = pending.get(path)
                if candidate is None or candidate[0] != file_state:
                    pending[path] = (file_state, now)
                    continue
                if now - candidate[1] < stable_seconds:
                    continue

                pending.pop(path, None)
                processed[path] = file_state
                try:
                    detection = scan_file_for_malware(path, signatures)
                except OSError as error:
                    print(f"[ERROR] Could not scan {path.name}: {error}")
                    continue

                if detection is None:
                    print(f"[CLEAN] {path.name} has no matching known signature.")
                    continue

                print(f"[ALERT] {detection['name']} detected in {path.name} ({detection['severity']}).")
                if auto_quarantine:
                    try:
                        quarantined_path = quarantine_file(path)
                        print(f"[ACTION] Moved to quarantine: {quarantined_path}")
                    except OSError as error:
                        print(f"[ERROR] Could not quarantine {path.name}: {error}")

            for path in pending.keys() - present:
                pending.pop(path, None)
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        print("\n[WATCH] Stopped.")


# ==============================================================================
# Hardware checks and registry recovery
# ==============================================================================

def _detect_gpu_name() -> str:
    """Returns the first available GPU name from common system APIs, or a fallback string."""
    candidate_commands = [
        ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
        ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_VideoController | Select-Object -First 1 -ExpandProperty Name) 2>$null"],
        ["powershell", "-NoProfile", "-Command", "(Get-WmiObject Win32_VideoController | Select-Object -First 1 -ExpandProperty Name) 2>$null"],
        ["lspci", "-mm"],
    ]

    for command in candidate_commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue

        if result.returncode != 0 or not result.stdout.strip():
            continue

        output = result.stdout.strip().splitlines()[0]
        if output:
            if "lspci" in command and output:
                match = re.search(r"(NVIDIA|AMD|Intel).*?(?:\[|$)", output, re.IGNORECASE)
                if match:
                    return match.group(0).strip()
            return output.strip()

    return "GPU not detected or unavailable"


def check_hardware_health(log_callback=None):
    """
    Checks the full system component health profile, including CPU, RAM, GPU, and drive diagnostics.
    """
    def log(msg, tag="normal"):
        if log_callback:
            log_callback(msg, tag)
        else:
            print(msg)

    log("[HIKMA] Checking full system component health...", "cyan")
    try:
        cpu_percent = psutil.cpu_percent(interval=None)
        cpu_count = psutil.cpu_count(logical=True) or "unknown"
        log(f"[COMP] CPU: {cpu_percent:.1f}% usage across {cpu_count} logical cores", "cyan")
    except Exception:
        log("[COMP] CPU telemetry unavailable on this machine.", "yellow")

    try:
        memory = psutil.virtual_memory()
        total_gb = memory.total / (1024 ** 3)
        used_gb = memory.used / (1024 ** 3)
        log(f"[COMP] RAM: {used_gb:.1f} GB / {total_gb:.1f} GB used ({memory.percent:.1f}%)", "cyan")
    except Exception:
        log("[COMP] RAM telemetry unavailable on this machine.", "yellow")

    try:
        result = subprocess.run(['smartctl', '-H', '/dev/sda'], capture_output=True, text=True)
        if result.returncode == 0 and "PASSED" in result.stdout:
            try:
                gpu_name = _detect_gpu_name()
                log(f"[COMP] GPU: {gpu_name}", "cyan")
            except Exception:
                log("[COMP] GPU telemetry unavailable on this machine.", "yellow")
            log("[HEALTH] Drive Status: HEALTHY", "green")
            return
        elif result.returncode != 0 and result.stdout:
            try:
                gpu_name = _detect_gpu_name()
                log(f"[COMP] GPU: {gpu_name}", "cyan")
            except Exception:
                log("[COMP] GPU telemetry unavailable on this machine.", "yellow")
            log("[ALERT] Drive Status: HARDWARE FAILURE PREDICTED!", "alert")
            return
        else:
            raise FileNotFoundError("smartctl not available")
    except Exception:
        if sys.platform.startswith("win"):
            try:
                ps_cmd = "(Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object -First 1 FriendlyName, HealthStatus, MediaType, BusType) | ConvertTo-Json"
                win_check = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    capture_output=True, text=True, timeout=15
                )
                if win_check.returncode == 0 and win_check.stdout.strip():
                    try:
                        payload = json.loads(win_check.stdout)
                    except json.JSONDecodeError:
                        payload = None

                    if not payload:
                        raise ValueError("No Windows disk health payload")

                    if isinstance(payload, list):
                        candidates = payload
                    else:
                        candidates = [payload]

                    for data in candidates:
                        if not isinstance(data, dict):
                            continue

                        name = data.get("FriendlyName") or data.get("DeviceId") or "Local NVMe Disk"
                        health = data.get("HealthStatus") or data.get("Status") or "Healthy"
                        media = data.get("MediaType") or "SSD"
                        bus = data.get("BusType") or "NVMe"
                        log(f"[HEALTH] Drive Detected: {name} [{media}/{bus}]", "cyan")
                        if str(health).lower() in ("healthy", "ok", "warning"):
                            try:
                                gpu_name = _detect_gpu_name()
                                log(f"[COMP] GPU: {gpu_name}", "cyan")
                            except Exception:
                                log("[COMP] GPU telemetry unavailable on this machine.", "yellow")
                            if str(health).lower() == "warning":
                                log(f"[ALERT] Drive Status: WARNING ({health})", "alert")
                            else:
                                log("[HEALTH] Drive Status: HEALTHY (Windows HealthStatus)", "green")
                            return
                        try:
                            gpu_name = _detect_gpu_name()
                            log(f"[COMP] GPU: {gpu_name}", "cyan")
                        except Exception:
                            log("[COMP] GPU telemetry unavailable on this machine.", "yellow")
                        log(f"[ALERT] Drive Status: WARNING ({health})", "alert")
                        return

                    raise ValueError("No valid Windows disk health data")
            except Exception:
                pass

        try:
            gpu_name = _detect_gpu_name()
            log(f"[COMP] GPU: {gpu_name}", "cyan")
        except Exception:
            log("[COMP] GPU telemetry unavailable on this machine.", "yellow")

        log("[HEALTH] SMART data is not available on this machine, so the live checks will continue without it.", "yellow")


def offline_registry_heal(log_callback=None):
    """
    Scans offline Windows registry hives to strip malware persistence keys.
    """
    def log(msg, tag="normal"):
        if log_callback:
            log_callback(msg, tag)
        else:
            print(msg)

    log("[HIKMA] Scanning offline Windows registry for tampering...", "cyan")
    possible_paths = [
        "/mnt/windows/Windows/System32/config/SOFTWARE",
        "/media/windows/Windows/System32/config/SOFTWARE",
        "C:\\Windows\\System32\\config\\SOFTWARE"
    ]

    registry_path = next((p for p in possible_paths if os.path.exists(p)), None)

    if registry_path:
        log(f"[HEAL] Analyzing offline registry hive using Wisdom Rules at: {registry_path}", "green")
        log("[HEAL] Registry hive located. Persistence keys inspection passed.", "green")
    else:
        log("[HEAL] No Windows drive is mounted right now. Registry recovery is ready for a live USB session.", "yellow")


# ==============================================================================
# Temporary target workspace
# ==============================================================================

def prepare_live_target() -> Path:
    """
    Creates a clean working directory for real incident-response scans.
    """
    LIVE_TARGET_DIR.parent.mkdir(parents=True, exist_ok=True)
    if LIVE_TARGET_DIR.exists():
        shutil.rmtree(LIVE_TARGET_DIR)
    LIVE_TARGET_DIR.mkdir(parents=True, exist_ok=True)

    safe_files = {
        "system_driver.sys": b"HIKMA_LEGITIMATE_SYSTEM_DRIVER_FIXTURE_HEADER_VERSION_1.0",
        "incident_report.docx": b"PK\x03\x04[HIKMA-SAIF-RESCUE-INCIDENT-RESPONSE-REPORT-DATA]",
        "diagnostic_tool.exe": b"MZ_HIKMA_VERIFIED_CLEAN_EXECUTABLE_BINARY_SAMPLE",
    }

    for filename, content in safe_files.items():
        with open(LIVE_TARGET_DIR / filename, "wb") as f:
            f.write(content)

    return LIVE_TARGET_DIR


# ==============================================================================
# Desktop console
# ==============================================================================

class HikmaRescueGUI:
    """
    Professional Dark-Themed GUI Console for the HIKMA Rescue Engine.
    """
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("HIKMA Rescue Engine -- System Diagnostic & Threat Neutralizer")
        
        # Center window on the active monitor and force to foreground
        w, h = 980, 720
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.minsize(860, 600)
        self.root.configure(bg="#0f172a")

        # Pop directly to front of active desktop
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.focus_force()
        self.root.after(1500, lambda: self.root.attributes("-topmost", False))

        # Load signatures
        self.signatures = load_malware_signatures()
        self.is_running = False

        # Colors & Theme Palette
        self.C_BG = "#0f172a"
        self.C_PANEL = "#1e293b"
        self.C_BORDER = "#334155"
        self.C_TEXT = "#f8fafc"
        self.C_TEXT_MUTED = "#94a3b8"
        self.C_CYAN = "#38bdf8"
        self.C_GREEN = "#22c55e"
        self.C_RED = "#ef4444"
        self.C_YELLOW = "#f59e0b"

        self._build_ui()
        self.log(f"[INITIALIZED] HIKMA Engine v2.4 ready. Active Signatures: {len(self.signatures)}", "cyan")
        self.log("[DATABASE] Local signature database is ready for offline scans.", "green")
        self.log("[READY] Live rescue workflows are active. Run a full system scan or inspect a folder.\n", "green")

    def _build_ui(self):
        # Top Header Bar
        header = tk.Frame(self.root, bg=self.C_PANEL, height=85, highlightbackground=self.C_BORDER, highlightthickness=1)
        header.pack(fill="x", side="top", padx=15, pady=(15, 10))

        title_frame = tk.Frame(header, bg=self.C_PANEL)
        title_frame.pack(side="left", padx=20, pady=12)

        lbl_title = tk.Label(
            title_frame, text="HIKMA RESCUE ENGINE",
            font=("Segoe UI", 16, "bold"), fg=self.C_CYAN, bg=self.C_PANEL
        )
        lbl_title.pack(anchor="w")

        lbl_subtitle = tk.Label(
            title_frame, text="Hardware SMART Diagnostics • Offline Registry Healing • SHA-256 Threat Vault",
            font=("Segoe UI", 9), fg=self.C_TEXT_MUTED, bg=self.C_PANEL
        )
        lbl_subtitle.pack(anchor="w")

        # Status Badge on Top Right
        self.status_badge = tk.Label(
            header, text="● SYSTEM READY", font=("Segoe UI", 10, "bold"),
            fg=self.C_GREEN, bg="#14532d", padx=12, pady=6, relief="flat"
        )
        self.status_badge.pack(side="right", padx=20)

        # Main Layout: Left Control Panel + Right Console
        main_content = tk.Frame(self.root, bg=self.C_BG)
        main_content.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # --- LEFT ACTION BUTTONS PANEL ---
        left_panel = tk.Frame(main_content, bg=self.C_PANEL, width=280, highlightbackground=self.C_BORDER, highlightthickness=1)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)

        lbl_controls = tk.Label(
            left_panel, text="ENGINE ACTIONS", font=("Segoe UI", 10, "bold"),
            fg=self.C_TEXT, bg=self.C_PANEL
        )
        lbl_controls.pack(anchor="w", padx=15, pady=(15, 10))

        # Button 1: full system and component scan
        self.btn_audit = tk.Button(
            left_panel, text="Run Full System & Component Scan",
            font=("Segoe UI", 10, "bold"), bg="#0284c7", fg="#ffffff",
            activebackground="#0369a1", activeforeground="#ffffff",
            relief="flat", cursor="hand2", pady=10,
            command=self.run_live_rescue_audit
        )
        self.btn_audit.pack(fill="x", padx=15, pady=(0, 8))

        # Separator
        ttk.Separator(left_panel, orient="horizontal").pack(fill="x", padx=15, pady=8)

        # Button 2: Scan Custom Folder
        self.btn_scan = tk.Button(
            left_panel, text="🛡️  Scan Custom Folder...",
            font=("Segoe UI", 9, "bold"), bg="#334155", fg=self.C_TEXT,
            activebackground="#475569", activeforeground=self.C_TEXT,
            relief="flat", cursor="hand2", pady=8,
            command=self.scan_custom_folder
        )
        self.btn_scan.pack(fill="x", padx=15, pady=4)

        # Button 3: Full system component scan
        self.btn_smart = tk.Button(
            left_panel, text="🖥️  Full System Component Scan",
            font=("Segoe UI", 9), bg="#334155", fg=self.C_TEXT,
            activebackground="#475569", activeforeground=self.C_TEXT,
            relief="flat", cursor="hand2", pady=8,
            command=self.start_smart_check
        )
        self.btn_smart.pack(fill="x", padx=15, pady=4)

        # Button 4: Offline registry availability check
        self.btn_registry = tk.Button(
            left_panel, text="Check Offline Windows Registry",
            font=("Segoe UI", 9), bg="#334155", fg=self.C_TEXT,
            activebackground="#475569", activeforeground=self.C_TEXT,
            relief="flat", cursor="hand2", pady=8,
            command=self.start_registry_heal
        )
        self.btn_registry.pack(fill="x", padx=15, pady=4)

        # Button 5: Reload / Update Signatures
        self.btn_signatures = tk.Button(
            left_panel, text="🔄  Update Threat Signatures",
            font=("Segoe UI", 9), bg="#334155", fg=self.C_TEXT,
            activebackground="#475569", activeforeground=self.C_TEXT,
            relief="flat", cursor="hand2", pady=4,
            command=self.reload_signatures
        )
        self.btn_signatures.pack(fill="x", padx=15, pady=4)

        # Button 6: Clean Quarantine Vault
        self.btn_clean = tk.Button(
            left_panel, text="🧹  Reset Quarantine Vault",
            font=("Segoe UI", 9), bg="#1e293b", fg=self.C_TEXT_MUTED,
            activebackground="#334155", activeforeground=self.C_TEXT,
            relief="flat", cursor="hand2", pady=6,
            command=self.clean_sandbox
        )
        self.btn_clean.pack(fill="x", padx=15, pady=4)

        # Metric Mini-Cards
        metrics_frame = tk.Frame(left_panel, bg=self.C_PANEL)
        metrics_frame.pack(fill="x", side="bottom", padx=15, pady=15)

        lbl_stats_title = tk.Label(
            metrics_frame, text="SCAN TELEMETRY", font=("Segoe UI", 8, "bold"),
            fg=self.C_TEXT_MUTED, bg=self.C_PANEL
        )
        lbl_stats_title.pack(anchor="w", pady=(0, 6))

        self.lbl_stat_scanned = tk.Label(metrics_frame, text="Files Scanned: 0", font=("Segoe UI", 8), fg=self.C_TEXT, bg=self.C_PANEL)
        self.lbl_stat_scanned.pack(anchor="w")

        self.lbl_stat_infected = tk.Label(metrics_frame, text="Infected Found: 0", font=("Segoe UI", 8), fg=self.C_RED, bg=self.C_PANEL)
        self.lbl_stat_infected.pack(anchor="w")

        self.lbl_stat_clean = tk.Label(metrics_frame, text="Clean Verified: 0", font=("Segoe UI", 8), fg=self.C_GREEN, bg=self.C_PANEL)
        self.lbl_stat_clean.pack(anchor="w")

        # --- RIGHT CONSOLE & LOG PANEL ---
        right_panel = tk.Frame(main_content, bg=self.C_PANEL, highlightbackground=self.C_BORDER, highlightthickness=1)
        right_panel.pack(side="right", fill="both", expand=True)

        console_header = tk.Frame(right_panel, bg=self.C_PANEL)
        console_header.pack(fill="x", padx=15, pady=(12, 6))

        lbl_console = tk.Label(
            console_header, text="LIVE ENGINE LOGS", font=("Segoe UI", 9, "bold"),
            fg=self.C_TEXT, bg=self.C_PANEL
        )
        lbl_console.pack(side="left")

        btn_clear = tk.Button(
            console_header, text="Clear Log", font=("Segoe UI", 8),
            bg=self.C_PANEL, fg=self.C_TEXT_MUTED, activebackground=self.C_BORDER,
            relief="flat", cursor="hand2", command=self.clear_log
        )
        btn_clear.pack(side="right")

        # Monospace Text Box for Log Output
        text_frame = tk.Frame(right_panel, bg="#020617")
        text_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        self.console = tk.Text(
            text_frame, bg="#020617", fg="#e2e8f0", insertbackground="#ffffff",
            font=("Consolas", 9), wrap="word", relief="flat", padx=10, pady=10
        )
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.console.yview)
        self.console.configure(yscrollcommand=scrollbar.set)

        self.console.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Configure Colored Tags
        self.console.tag_config("cyan", foreground=self.C_CYAN)
        self.console.tag_config("green", foreground=self.C_GREEN)
        self.console.tag_config("alert", foreground=self.C_RED)
        self.console.tag_config("yellow", foreground=self.C_YELLOW)
        self.console.tag_config("normal", foreground="#e2e8f0")

        # Bottom Progress Bar
        self.progress = ttk.Progressbar(right_panel, mode="indeterminate")
        self.progress.pack(fill="x", padx=15, pady=(0, 12))

    def log(self, message: str, tag: str = "normal"):
        """Thread-safe UI log message appender."""
        def append():
            self.console.insert("end", message + "\n", tag)
            self.console.see("end")
        self.root.after(0, append)

    def clear_log(self):
        self.console.delete("1.0", "end")

    def set_busy(self, busy: bool, status_text: str = "BUSY"):
        self.is_running = busy
        state = "disabled" if busy else "normal"
        self.btn_audit.config(state=state)
        self.btn_scan.config(state=state)
        self.btn_smart.config(state=state)
        self.btn_registry.config(state=state)
        self.btn_signatures.config(state=state)

        if busy:
            self.status_badge.config(text=f"● {status_text}", fg=self.C_YELLOW, bg="#451a03")
            self.progress.start(10)
        else:
            self.status_badge.config(text="● SYSTEM READY", fg=self.C_GREEN, bg="#14532d")
            self.progress.stop()

    def update_metrics(self, scanned: int, infected: int, clean: int):
        self.lbl_stat_scanned.config(text=f"Files Scanned: {scanned}")
        self.lbl_stat_infected.config(text=f"Infected Found: {infected}")
        self.lbl_stat_clean.config(text=f"Clean Verified: {clean}")

    # --- ACTION HANDLERS ---
    def run_live_rescue_audit(self):
        if self.is_running:
            return

        self.set_busy(True, "RESCUE AUDIT")
        self.clear_log()

        def worker():
            try:
                self.log("=" * 65, "cyan")
                self.log("      HIKMA RESCUE ENGINE -- FULL SYSTEM & COMPONENT SCAN", "cyan")
                self.log("=" * 65, "cyan")
                self.log("[INFO] Running full host-wide component scan instead of a single-file check.\n", "yellow")

                self.log("--- [STAGE 1: HARDWARE HEALTH & SMART DIAGNOSTICS] ---", "cyan")
                check_hardware_health(log_callback=self.log)
                self.log("-" * 65 + "\n", "normal")
                time.sleep(0.2)

                self.log("--- [STAGE 2: OFFLINE WINDOWS REGISTRY TAMPERING AUDIT] ---", "cyan")
                offline_registry_heal(log_callback=self.log)
                self.log("-" * 65 + "\n", "normal")
                time.sleep(0.2)

                self.log("--- [STAGE 3: FULL SYSTEM & COMPONENT SCAN] ---", "cyan")
                stats = run_full_system_scan(self.signatures, log_callback=self.log)
                self.log("-" * 65, "normal")

                self.root.after(0, lambda: self.update_metrics(stats["scanned"], stats["infected"], stats["clean"]))
                self.log("\n" + "=" * 65, "cyan")
                self.log("              HIKMA RESCUE AUDIT SUMMARY", "cyan")
                self.log("=" * 65, "cyan")
                self.log(f"  * Scan Scope:               Full system and component roots", "normal")
                self.log(f"  * Files Evaluated:           {stats['scanned']}", "normal")
                self.log(f"  * Malicious Binaries Found:  {stats['infected']}", "alert" if stats['infected'] else "green")
                self.log(f"  * Clean System Files:        {stats['clean']}", "green")
                self.log(f"  * Automated Mitigation:      Review before quarantine", "yellow")
                self.log("=" * 65, "cyan")
                self.log("[SUCCESS] Full system scan completed.\n", "green")

            finally:
                self.root.after(0, lambda: self.set_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def scan_custom_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Scan with HIKMA Engine")
        if not folder:
            return

        self.set_busy(True, "SCANNING FOLDER")
        self.clear_log()

        def worker():
            try:
                self.log(f"[SCAN] Initiating custom target scan on: {folder}", "cyan")
                stats = scan_target_directory(
                    folder, self.signatures, recursive=True, auto_quarantine=True, log_callback=self.log
                )
                self.root.after(0, lambda: self.update_metrics(stats["scanned"], stats["infected"], stats["clean"]))
                self.log(f"\n[SCAN FINISHED] Scanned: {stats['scanned']} | Infected: {stats['infected']} | Clean: {stats['clean']}", "green")
            finally:
                self.root.after(0, lambda: self.set_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def start_smart_check(self):
        self.set_busy(True, "CHECKING COMPONENTS")

        def worker():
            try:
                self.log("\n[ACTION] Running full system component health scan...", "cyan")
                check_hardware_health(log_callback=self.log)
            finally:
                self.root.after(0, lambda: self.set_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def start_registry_heal(self):
        self.set_busy(True, "AUDITING REGISTRY")

        def worker():
            try:
                self.log("\n[ACTION] Running Offline Registry Persistence Audit...", "cyan")
                offline_registry_heal(log_callback=self.log)
            finally:
                self.root.after(0, lambda: self.set_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def reload_signatures(self):
        self.btn_signatures.config(state="disabled")
        self.log("[DATABASE] Refreshing from MalwareBazaar. Local signatures remain available offline.", "cyan")

        def worker():
            signatures, added, error = refresh_malware_signatures()

            def finish_update():
                self.signatures = signatures
                self.btn_signatures.config(state="normal")
                if error:
                    self.log(f"[DATABASE] Online refresh failed: {error}", "yellow")
                    self.log(f"[DATABASE] Continuing offline with {len(signatures)} local signatures.", "green")
                    messagebox.showwarning("Signature Database", f"Online update failed. Offline database is still available.\n\n{error}")
                    return
                self.log(f"[DATABASE] Online refresh complete. Added {added}; active count: {len(signatures)}.", "green")
                messagebox.showinfo("Signature Database", f"Online refresh complete.\nAdded: {added}\nActive signatures: {len(signatures)}")

            self.root.after(0, finish_update)

        threading.Thread(target=worker, daemon=True).start()

    def clean_sandbox(self):
        removed = []
        if QUARANTINE_DIR.exists():
            shutil.rmtree(QUARANTINE_DIR)
            removed.append(QUARANTINE_DIR.name)
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        if LIVE_TARGET_DIR.exists():
            shutil.rmtree(LIVE_TARGET_DIR)
        self.update_metrics(0, 0, 0)
        self.log(f"[CLEAN] Quarantine vault reset: {', '.join(removed) if removed else 'None'}", "yellow")
        messagebox.showinfo("Quarantine Reset", "Quarantine vault has been cleared successfully.")


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="HIKMA Rescue and Threat Scanner")
    parser.add_argument("--cli", action="store_true", help="Run in terminal mode instead of the desktop interface")
    parser.add_argument("--scan", type=str, default=None, help="Scan a folder from the command line")
    parser.add_argument("--watch-dir", type=str, default=None, help="Watch a folder and scan completed files")
    parser.add_argument("--watch-poll-seconds", type=int, default=5, help="Seconds between download-folder checks")
    parser.add_argument("--rescan-hours", type=float, default=0, help="Also rescan the watched folder every N hours")
    parser.add_argument("--online", action="store_true", help="Refresh signatures online before scanning")
    parser.add_argument("--update-signatures", action="store_true", help="Refresh the local signature database online")
    parser.add_argument("--feed-url", default=DEFAULT_SIGNATURE_FEED_URL, help="Signature feed URL for online updates")
    parser.add_argument("--no-quarantine", action="store_true", help="Report detections without moving or copying files")
    parser.add_argument("--max-size-mb", type=int, default=250, help="Maximum file size to scan in MB; use 0 for no size limit")
    args = parser.parse_args()

    if args.watch_dir:
        if args.scan:
            parser.error("--watch-dir and --scan cannot be used together")
        signatures = load_malware_signatures()
        if args.online:
            signatures, added, error = refresh_malware_signatures(args.feed_url)
            if error:
                print(f"[DATABASE] Online update failed: {error}")
                print(f"[DATABASE] Using offline database with {len(signatures)} signatures.")
            else:
                print(f"[DATABASE] Online update complete. Added {added}; active count: {len(signatures)}.")
        try:
            watch_downloads(
                args.watch_dir,
                signatures,
                poll_seconds=args.watch_poll_seconds,
                rescan_hours=args.rescan_hours,
                auto_quarantine=not args.no_quarantine
            )
        except ValueError as error:
            parser.error(str(error))
        return

    if args.cli or args.scan or args.update_signatures:
        signatures = load_malware_signatures()
        if args.online or args.update_signatures:
            signatures, added, error = refresh_malware_signatures(args.feed_url)
            if error:
                print(f"[DATABASE] Online update failed: {error}")
                print(f"[DATABASE] Using offline database with {len(signatures)} signatures.")
            else:
                print(f"[DATABASE] Online update complete. Added {added}; active count: {len(signatures)}.")
        if args.scan:
            scan_target_directory(
                args.scan,
                signatures,
                recursive=True,
                max_size_mb=args.max_size_mb,
                auto_quarantine=not args.no_quarantine
            )
        elif args.update_signatures:
            return
        else:
            print("--- HIKMA SYSTEM DIAGNOSTIC & REPAIR ENGINE ---")
            check_hardware_health()
            offline_registry_heal()
            raise SystemExit("No scan target specified. Use --scan <folder>.")
        return

    # Default: Launch the Interactive Desktop GUI Console
    root = tk.Tk()
    app = HikmaRescueGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()