from unittest.mock import patch

import snap_it


def test_capture_local_no_chromium():
    with patch("shutil.which", return_value=None), patch("builtins.print") as mock_print:
        snap_it.capture_local("some_file.py")
        mock_print.assert_called_once_with("[!] Error: Chromium not found. Run: pkg install chromium")


def test_capture_local_file_not_found():
    with patch("shutil.which", return_value="/usr/bin/chromium"), patch("os.path.exists", return_value=False), patch("builtins.print") as mock_print:
        snap_it.capture_local("missing_file.py")
        mock_print.assert_called_once_with("[-] Missing: missing_file.py")
