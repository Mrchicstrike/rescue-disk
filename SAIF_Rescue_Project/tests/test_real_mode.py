import inspect
import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import main


def test_system_audit_uses_full_system_roots_instead_of_prompt():
    calls = []

    def fake_scan(directory, signatures, recursive=True, auto_quarantine=True, log_callback=None):
        calls.append(Path(directory))
        return {"scanned": 1, "infected": 0, "clean": 1, "errors": 0, "skipped_size": 0, "detections": []}

    with patch.object(main, "discover_system_scan_roots", return_value=[Path("/tmp/one"), Path("/tmp/two")]), \
         patch.object(main, "check_hardware_health"), \
         patch.object(main, "offline_registry_heal"), \
         patch.object(main, "scan_target_directory", side_effect=fake_scan):
        stats = main.run_full_system_scan(signatures={}, log_callback=lambda *args, **kwargs: None)

    assert stats["scanned"] == 2
    assert calls == [Path("/tmp/one"), Path("/tmp/two")]


def test_hardware_health_does_not_claim_demo_mode():
    original_run = main.subprocess.run
    main.subprocess.run = lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("smartctl unavailable"))

    try:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main.check_hardware_health(log_callback=lambda msg, tag="normal": print(msg))

        output = buffer.getvalue()
        assert "DEMO EMULATION" not in output
        assert "simulation/test mode" not in output
    finally:
        main.subprocess.run = original_run


def test_gui_has_no_demo_button_text():
    source = inspect.getsource(main.HikmaRescueGUI._build_ui)
    assert "RUN FULL SHOWCASE DEMO" not in source
