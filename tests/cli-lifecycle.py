"""Opt-in Windows CLI system-proxy lifecycle acceptance, without elevation.

Run only while another NullAD instance is not managing the system proxy:
  python tests/cli-lifecycle.py --cli <absolute-exe> --output <report.json> \
      --allow-system-proxy

Captures all four raw registry values (including presence and type) before
launch. Every child has its own NULLAD_HOME and hidden, independent console.
Checks default no-change mode, a failed DNS bind, and opt-in apply/restore.
A separate helper attaches to the child's console to send Ctrl+Break. The
finally block restores the original raw baseline if any stage leaves a change.
Full values stay in the isolated work directory; the output report is redacted.
"""

import argparse
import contextlib
import ctypes
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

if os.name == "nt":
    import winreg

REGISTRY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
REGISTRY_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")


class SignalUnavailable(RuntimeError):
    pass


def read_proxy():
    state = {}
    registry = ctypes.WinDLL("advapi32", use_last_error=True)
    registry.RegQueryValueExW.argtypes = (
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    )
    registry.RegQueryValueExW.restype = ctypes.c_long
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY) as key:
        for name in REGISTRY_VALUES:
            try:
                value, value_type = winreg.QueryValueEx(key, name)
                raw_type, size = ctypes.c_uint32(), ctypes.c_uint32()
                error = registry.RegQueryValueExW(
                    int(key), name, None, ctypes.byref(raw_type), None, ctypes.byref(size)
                )
                if error:
                    raise ctypes.WinError(error)
                data = (ctypes.c_ubyte * max(size.value, 1))()
                error = registry.RegQueryValueExW(
                    int(key), name, None, ctypes.byref(raw_type), data, ctypes.byref(size)
                )
                if error:
                    raise ctypes.WinError(error)
                state[name] = {
                    "exists": True, "type": value_type,
                    "value": value if not isinstance(value, bytes) else None,
                    "raw_bytes": list(data[:size.value]),
                }
            except FileNotFoundError:
                state[name] = {"exists": False}
    return state


def normalized(state):
    def value(name, default=None):
        return state[name].get("value", default)

    return {
        "enabled": bool(value("ProxyEnable", 0)),
        "server": value("ProxyServer") or None,
        "bypass": value("ProxyOverride") or None,
        "auto_config_url": value("AutoConfigURL") or None,
    }


def redacted(state):
    return {
        "enabled": normalized(state)["enabled"],
        "fields": {
            name: {
                "exists": entry["exists"],
                "type": entry.get("type"),
                "byte_length": len(entry.get("raw_bytes", [])) if entry["exists"] else None,
            }
            for name, entry in state.items()
        },
    }


def read_dns():
    # Read resolver state without applying settings or requiring elevation.
    command = (
        "ConvertTo-Json -Depth 6 -Compress -InputObject @("
        "Get-DnsClientServerAddress -ErrorAction Stop | "
        "Sort-Object InterfaceIndex,AddressFamily | "
        "Select-Object InterfaceIndex,AddressFamily,ServerAddresses)"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if completed.returncode:
        raise RuntimeError(f"read-only DNS capture failed: {completed.stderr.strip()}")
    return json.loads(completed.stdout)


def restore_proxy(state):
    registry = ctypes.WinDLL("advapi32", use_last_error=True)
    registry.RegSetValueExW.argtypes = (
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32,
        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
    )
    registry.RegSetValueExW.restype = ctypes.c_long
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, REGISTRY_KEY, 0, winreg.KEY_SET_VALUE
    ) as key:
        for name, entry in state.items():
            if entry["exists"]:
                raw = bytes(entry["raw_bytes"])
                data = ctypes.create_string_buffer(raw)
                error = registry.RegSetValueExW(int(key), name, 0, entry["type"], data, len(raw))
                if error:
                    raise ctypes.WinError(error)
            else:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
    wininet = ctypes.WinDLL("wininet", use_last_error=True)
    wininet.InternetSetOptionW.argtypes = (
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32
    )
    wininet.InternetSetOptionW.restype = ctypes.c_int
    for option in (39, 37):  # SETTINGS_CHANGED, REFRESH
        wininet.InternetSetOptionW(None, option, None, 0)


def signal_helper(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.AttachConsole.argtypes = (ctypes.c_uint32,)
    kernel.AttachConsole.restype = ctypes.c_int
    kernel.GenerateConsoleCtrlEvent.argtypes = (ctypes.c_uint32, ctypes.c_uint32)
    kernel.GenerateConsoleCtrlEvent.restype = ctypes.c_int
    handler_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint32)
    kernel.SetConsoleCtrlHandler.argtypes = (handler_type, ctypes.c_int)
    kernel.SetConsoleCtrlHandler.restype = ctypes.c_int
    kernel.FreeConsole()
    if not kernel.AttachConsole(pid):
        raise ctypes.WinError(ctypes.get_last_error())
    handler = handler_type(lambda _event: 1)
    try:
        if not kernel.SetConsoleCtrlHandler(handler, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GenerateConsoleCtrlEvent(1, 0):  # CTRL_BREAK_EVENT
            raise ctypes.WinError(ctypes.get_last_error())
        time.sleep(0.1)
    finally:
        kernel.FreeConsole()


def send_break(process):
    helper = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--send-break", str(process.pid)],
        capture_output=True, text=True, timeout=5,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if helper.returncode:
        raise SignalUnavailable(helper.stderr.strip() or "console signal helper failed")


def pending_count(home):
    journal = home / "data" / "change-journal.json"
    return len(json.loads(journal.read_text())["entries"]) if journal.exists() else 0


def wait_running(process, log):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        output = log.read_text(encoding="utf-8", errors="replace")
        if "running. press Ctrl+C" in output:
            match = re.search(r"HTTP proxy listening on http://127\.0\.0\.1:(\d+)", output)
            if match:
                return int(match.group(1))
        if process.poll() is not None:
            raise AssertionError(f"CLI exited before ready ({process.returncode}): {output}")
        time.sleep(0.02)
    raise TimeoutError("CLI did not become ready within 10 seconds")


def check_rebind(port):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
        listener.listen()


def terminate_children(processes):
    for process in processes:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)


def run_acceptance(cli, output):
    report = {"status": "Unknown", "stages": [], "fallback_restore_required": False}
    baseline = read_proxy()
    baseline_dns = read_dns()
    repo = Path(__file__).resolve().parents[1]
    root = Path(tempfile.mkdtemp(prefix="cli-lifecycle-", dir=repo.parent))
    report["isolated_home_root"] = str(root)
    report["baseline_redacted"] = redacted(baseline)
    (root / "system-proxy-baseline.json").write_text(
        json.dumps({"proxy": baseline, "dns": baseline_dns}, indent=2), encoding="utf-8"
    )
    processes = []
    # Persist the recovery baseline before the first possible OS write.
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    try:
        # Retain isolated journals and logs as evidence if a stage fails.
        with contextlib.ExitStack() as cleanup:
            cleanup.callback(terminate_children, processes)

            def launch(name, flags):
                home = root / name
                home.mkdir()
                log = home / "cli.log"
                env = os.environ.copy()
                env["NULLAD_HOME"] = str(home)
                startup = subprocess.STARTUPINFO()
                startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startup.wShowWindow = 0  # SW_HIDE
                with log.open("wb") as stdout:
                    process = subprocess.Popen(
                        [str(cli), "serve", "--port", "0", *flags], cwd=repo,
                        env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                        stderr=subprocess.STDOUT, startupinfo=startup,
                        creationflags=subprocess.CREATE_NEW_CONSOLE,
                    )
                processes.append(process)
                return process, home, log

            # Establish that Ctrl+Break reaches this executable before OS mutation.
            process, home, log = launch("default", [])
            port = wait_running(process, log)
            assert read_proxy() == baseline, "default serve modified OS settings"
            send_break(process)
            assert process.wait(timeout=10) == 0, log.read_text(errors="replace")
            assert read_proxy() == baseline, "default exit modified OS settings"
            assert pending_count(home) == 0
            check_rebind(port)
            report["stages"].append({"name": "default_no_os_change_ctrl_break", "status": "Pass"})

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
                occupied.bind(("127.0.0.1", 0))
                process, home, log = launch(
                    "bind-failure", ["--system-proxy", "--dns-port", str(occupied.getsockname()[1])]
                )
                assert process.wait(timeout=10) != 0, "occupied DNS bind unexpectedly succeeded"
                assert read_proxy() == baseline, "failed listener bind modified OS settings"
                assert pending_count(home) == 0, "failed bind created a recovery snapshot"
            report["stages"].append({"name": "all_binds_before_apply", "status": "Pass"})

            process, home, log = launch("system-proxy", ["--system-proxy"])
            port = wait_running(process, log)
            applied = normalized(read_proxy())
            assert applied["enabled"] and applied["server"] == f"127.0.0.1:{port}", applied
            assert applied["auto_config_url"] is None, "fixed proxy did not clear PAC"
            assert pending_count(home) == 1, "original snapshot was not persisted"
            send_break(process)
            assert process.wait(timeout=10) == 0, log.read_text(errors="replace")
            restored = read_proxy()
            report["readback_redacted"] = redacted(restored)
            (root / "system-proxy-readback.json").write_text(json.dumps(restored, indent=2), encoding="utf-8")
            assert normalized(restored) == normalized(baseline), "proxy settings were not restored"
            assert restored == baseline, "raw registry baseline differs after CLI restore"
            assert pending_count(home) == 0, "verified restore left a pending snapshot"
            check_rebind(port)
            report["stages"].append({
                "name": "explicit_apply_stop_restore", "status": "Pass",
                "port": port, "pending_after_exit": 0, "raw_baseline_equal": True,
                "output": log.read_text(encoding="utf-8", errors="replace"),
            })
            report["status"] = "Pass"
    except SignalUnavailable as error:
        report["status"] = "Unknown"
        report["reason"] = str(error)
    except Exception as error:
        report["status"] = "Fail"
        report["reason"] = f"{type(error).__name__}: {error}"
    finally:
        try:
            terminate_children(processes)
        except Exception as error:
            report["status"] = "Fail"
            report["process_cleanup_error"] = f"{type(error).__name__}: {error}"
        try:
            if read_proxy() != baseline:
                report["fallback_restore_required"] = True
                restore_proxy(baseline)
            report["final_raw_baseline_equal"] = read_proxy() == baseline
            if not report["final_raw_baseline_equal"]:
                raise AssertionError("final raw baseline readback differs")
            final_dns = read_dns()
            report["dns_unchanged"] = final_dns == baseline_dns
            (root / "dns-readback.json").write_text(json.dumps(final_dns, indent=2), encoding="utf-8")
            if not report["dns_unchanged"]:
                raise AssertionError("DNS changed during CLI acceptance")
        except Exception as error:
            report["status"] = "Fail"
            report["recovery_error"] = f"{type(error).__name__}: {error}"
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"status": report["status"], "report": str(output), "stages": report["stages"]}))
    return 1 if report["status"] == "Fail" else 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--send-break":
        signal_helper(int(sys.argv[2]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-system-proxy", required=True, action="store_true")
    args = parser.parse_args()
    if os.name != "nt":
        print("Unknown: this acceptance harness requires Windows console APIs")
        return 0
    return run_acceptance(args.cli.resolve(strict=True), args.output.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
