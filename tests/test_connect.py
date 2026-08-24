"""Тесты connect: парсинг plist, разбор ошибок libimobiledevice.

connect tests: plist parsing, libimobiledevice error handling.
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import connect  # noqa: E402

SAMPLE_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeviceName</key><string>iPhone</string>
    <key>ProductVersion</key><string>27.0</string>
    <key>UniqueDeviceID</key><string>00008150-0005243E2181401C</string>
    <key>ActivationState</key><string>Activated</string>
    <key>BatteryIsCharging</key><true/>
</dict>
</plist>
"""


def fake_run(stdout="", stderr="", returncode=0):
    proc = mock.Mock()
    proc.stdout, proc.stderr, proc.returncode = stdout, stderr, returncode
    return proc


class TestRunErrorMapping(unittest.TestCase):
    @mock.patch.object(connect.subprocess, "run")
    def test_missing_tool_hint(self, run):
        run.side_effect = FileNotFoundError()
        with self.assertRaises(connect.DeviceError) as ctx:
            connect._run(["ideviceinfo", "-x"])
        self.assertIn("libimobiledevice-utils", str(ctx.exception))

    @mock.patch.object(connect.subprocess, "run")
    def test_unable_to_retrieve_device_list(self, run):
        run.return_value = fake_run(stderr="ERROR: Unable to retrieve device list!", returncode=255)
        with self.assertRaises(connect.DeviceError) as ctx:
            connect.list_devices()
        self.assertIn("usbmuxd", str(ctx.exception))

    @mock.patch.object(connect.subprocess, "run")
    def test_no_device(self, run):
        run.return_value = fake_run(stderr="No device found", returncode=1)
        with self.assertRaises(connect.DeviceError) as ctx:
            connect.list_devices()
        self.assertIn("Доверять", str(ctx.exception))

    @mock.patch.object(connect.subprocess, "run")
    def test_not_paired(self, run):
        run.return_value = fake_run(stderr="Could not connect to lockdownd", returncode=1)
        with self.assertRaises(connect.DeviceError) as ctx:
            connect.device_info("X")
        self.assertIn("не спарено", str(ctx.exception).lower())

    @mock.patch.object(connect.subprocess, "run")
    def test_generic_error_passthrough(self, run):
        run.return_value = fake_run(stderr="boom", returncode=2)
        with self.assertRaises(connect.DeviceError) as ctx:
            connect._run(["ideviceinfo"])
        self.assertIn("boom", str(ctx.exception))


class TestDeviceParsing(unittest.TestCase):
    @mock.patch.object(connect.subprocess, "run")
    def test_list_devices_parses_lines(self, run):
        run.return_value = fake_run(stdout="udid-one\n\nudid-two\n")
        self.assertEqual(connect.list_devices(), ["udid-one", "udid-two"])

    @mock.patch.object(connect.subprocess, "run")
    def test_device_info_parses_types(self, run):
        run.return_value = fake_run(stdout=SAMPLE_PLIST)
        info = connect.device_info("UDID")
        self.assertEqual(info["DeviceName"], "iPhone")
        self.assertIs(info["BatteryIsCharging"], True)
        self.assertEqual(info["ProductVersion"], "27.0")

    def test_summary_fields_and_defaults(self):
        rows = connect.summary({"DeviceName": "iPhone"})
        titles = [t for t, _ in rows]
        self.assertIn("Имя устройства", titles)
        self.assertIn("Версия iOS", titles)
        missing = dict(rows)["Серийный номер"]
        self.assertEqual(missing, "n/a")


if __name__ == "__main__":
    unittest.main()
