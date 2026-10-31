import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import main


def test_merge_signature_record_from_hash_dict():
    digest = "a" * 64
    feed = {
        digest: {
            "name": "SampleRansomware",
            "family": "Ransomware",
            "severity": "CRITICAL",
            "description": "Sample ransomware hash"
        }
    }
    result = main.merge_signature_feed(feed)
    assert result[digest]["name"] == "SampleRansomware"
    assert "abc123" not in result


def test_merge_signature_record_from_list():
    digest = "b" * 64
    feed = [{
        "sha256": digest,
        "name": "TestTrojan",
        "family": "Trojan",
        "severity": "HIGH",
        "description": "Known trojan sample"
    }]
    result = main.merge_signature_feed(feed)
    assert result[digest]["name"] == "TestTrojan"


def test_merge_malwarebazaar_text_hash_feed():
    digest = "c" * 64
    feed = f"# MalwareBazaar recent SHA256 hashes\nsha256_hash\n{digest}\nnot-a-hash\n"

    result = main.merge_signature_feed(feed)

    assert list(result) == [digest]
    assert result[digest]["family"] == "Malware"


def test_refresh_persists_signatures_for_offline_use():
    digest = "d" * 64
    with tempfile.TemporaryDirectory() as temp_dir:
        db_file = Path(temp_dir) / "signatures.json"
        with patch.object(main, "fetch_signature_feed", return_value=digest):
            signatures, added, error = main.refresh_malware_signatures("https://feed.invalid", db_file)

        assert error is None
        assert added == 1
        assert digest in json.loads(db_file.read_text(encoding="utf-8"))
        assert digest in main.load_malware_signatures(db_file)


def test_refresh_failure_keeps_local_database():
    digest = "e" * 64
    with tempfile.TemporaryDirectory() as temp_dir:
        db_file = Path(temp_dir) / "signatures.json"
        db_file.write_text(json.dumps({digest: {"name": "CachedThreat"}}), encoding="utf-8")
        with patch.object(main, "fetch_signature_feed", return_value=None):
            signatures, added, error = main.refresh_malware_signatures("https://feed.invalid", db_file)

        assert error is not None
        assert added == 0
        assert signatures[digest]["name"] == "CachedThreat"


def test_unlimited_scan_size_includes_large_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        target = Path(temp_dir) / "large-sample.bin"
        target.write_bytes(b"sample")
        with patch.object(main, "calculate_sha256", return_value=None):
            stats = main.scan_target_directory(temp_dir, {}, max_size_mb=0)

        assert stats["scanned"] == 1
        assert stats["skipped_size"] == 0


def test_hash_failure_is_reported_as_scan_error_not_clean():
    with tempfile.TemporaryDirectory() as temp_dir:
        target = Path(temp_dir) / "unreadable.bin"
        target.write_bytes(b"sample")
        with patch.object(main, "calculate_sha256", return_value=None):
            stats = main.scan_target_directory(temp_dir, {})

    assert stats["scanned"] == 1
    assert stats["clean"] == 0
    assert stats["errors"] == 1


def test_quarantine_uses_distinct_names_for_same_named_files():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        first = root / "first" / "sample.bin"
        second = root / "second" / "sample.bin"
        vault = root / "vault"
        first.parent.mkdir()
        second.parent.mkdir()
        first.write_bytes(b"first threat")
        second.write_bytes(b"second threat")

        with patch.object(main, "QUARANTINE_DIR", vault):
            first_target = main.quarantine_file(first)
            second_target = main.quarantine_file(second)

        assert first_target != second_target
        assert first_target.read_bytes() == b"first threat"
        assert second_target.read_bytes() == b"second threat"
        assert not first.exists()
        assert not second.exists()


def test_quarantine_failure_is_reported_and_source_is_retained():
    detection = {
        "path": "sample.bin",
        "filename": "sample.bin",
        "sha256": "f" * 64,
        "name": "TestThreat",
        "family": "Test",
        "severity": "HIGH",
        "description": "Test detection"
    }
    with tempfile.TemporaryDirectory() as temp_dir:
        target = Path(temp_dir) / "sample.bin"
        target.write_bytes(b"threat")
        messages = []
        with patch.object(main, "scan_file_for_malware", return_value=detection), \
             patch.object(main, "quarantine_file", side_effect=OSError("move blocked")):
            stats = main.scan_target_directory(
                temp_dir, {}, auto_quarantine=True,
                log_callback=lambda message, tag="normal": messages.append(message)
            )

        assert target.exists()
        assert stats["infected"] == 1
        assert stats["errors"] == 1
        assert any("Could not quarantine" in message for message in messages)
        assert not any("Moved to quarantine" in message for message in messages)


def test_download_watcher_scans_stable_files_and_skips_partial_downloads():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        completed = root / "finished.bin"
        partial = root / "still-downloading.bin.crdownload"
        completed.write_bytes(b"finished")
        partial.write_bytes(b"partial")
        scans = []

        with patch.object(main.time, "monotonic", side_effect=[0, 11]), \
             patch.object(main.time, "sleep", side_effect=[None, KeyboardInterrupt]), \
             patch.object(main, "scan_file_for_malware", side_effect=lambda path, signatures: scans.append(path) or None):
            main.watch_downloads(root, {}, auto_quarantine=False)

        assert scans == [completed]


def test_windows_health_check_does_not_invent_smart_results():
    windows_disk = SimpleNamespace(
        returncode=0,
        stdout='{"FriendlyName":"Disk","HealthStatus":"Healthy","MediaType":"SSD","BusType":"NVMe"}'
    )
    messages = []

    with patch.object(main.sys, "platform", "win32"), \
         patch.object(main.subprocess, "run", side_effect=[FileNotFoundError(), windows_disk]):
        main.check_hardware_health(log_callback=lambda message, tag="normal": messages.append(message))

    assert any("Windows HealthStatus" in message for message in messages)
    assert not any("SMART Self-Test" in message for message in messages)
    assert not any("SMART Attributes" in message for message in messages)


def test_windows_health_check_handles_json_array_disk_payloads():
    windows_disks = SimpleNamespace(
        returncode=0,
        stdout='[{"FriendlyName":"Disk","HealthStatus":"Healthy","MediaType":"SSD","BusType":"NVMe"}]'
    )
    messages = []

    with patch.object(main.sys, "platform", "win32"), \
         patch.object(main.subprocess, "run", side_effect=[FileNotFoundError(), windows_disks]):
        main.check_hardware_health(log_callback=lambda message, tag="normal": messages.append(message))

    assert any("Drive Detected" in message for message in messages)
    assert any("Windows HealthStatus" in message for message in messages)
    assert not any("SMART data is not available on this machine" in message for message in messages)


def test_windows_health_check_uses_a_reasonable_timeout_for_powershell():
    windows_disk = SimpleNamespace(
        returncode=0,
        stdout='{"FriendlyName":"Disk","HealthStatus":"Healthy","MediaType":"SSD","BusType":"NVMe"}'
    )
    captured = {'timeouts': []}
    calls = {'count': 0}

    def fake_run(*args, **kwargs):
        calls['count'] += 1
        if calls['count'] == 1:
            raise FileNotFoundError()
        captured['timeouts'].append(kwargs['timeout'])
        return windows_disk

    with patch.object(main.sys, "platform", "win32"), \
         patch.object(main.subprocess, "run", side_effect=fake_run):
        main.check_hardware_health(log_callback=lambda message, tag="normal": None)

    assert max(captured['timeouts']) >= 10


def test_component_health_scan_reports_cpu_ram_and_gpu():
    messages = []

    with patch.object(main.psutil, "cpu_percent", return_value=31.5), \
         patch.object(main.psutil, "cpu_count", return_value=8), \
         patch.object(main.psutil, "virtual_memory", return_value=SimpleNamespace(total=16 * 1024**3, used=8 * 1024**3, percent=50.0)), \
         patch.object(main, "_detect_gpu_name", return_value="NVIDIA GeForce RTX 4070"), \
         patch.object(main.subprocess, "run", side_effect=FileNotFoundError("smartctl unavailable")):
        main.check_hardware_health(log_callback=lambda message, tag="normal": messages.append(message))

    assert any("CPU" in message and "31.5%" in message for message in messages)
    assert any("RAM" in message and "50.0%" in message for message in messages)
    assert any("GPU" in message and "NVIDIA GeForce RTX 4070" in message for message in messages)
