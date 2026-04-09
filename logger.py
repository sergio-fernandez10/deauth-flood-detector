"""
=============================================================================
logger.py — Alert Logger
=============================================================================
Writes alert records to a log file when a deauth flood is detected.

Log format:
    [YYYY-MM-DD HH:MM:SS] FLOOD |MAC: xx:xx:xx:xx:xx:xx | Count: # |
    Reason Code: #
============================================================================
"""

import time

class Logger:
    """
    Appends structured alert records to a log file.
        - Existing files are never overwritten.
        - Multiple sessions accumulated in the same file.
        - Safe to monitor live with: tail -f deauth_alert.log
    """

    def __init__(self, log_file: str):
        """
        Initialize the logger.

        :param log_file: Path to the log file.
        """
        self.log_file = log_file
        self._write_session_header()

    def _write_session_header(self):
        """
        Writes a session start header to the log file so multiple sessions
        are easily distinguished when reviewing.
        """
        readable_time = time.strftime("%Y-%m-%d %H:%M:%S")
        header = (
            f"\n{'=' * 60}\n"
            f"  SESSION STARTED: {readable_time}\n"
            f"{'=' * 60}\n"
        )
        self._append(header)

    def log(self, alert: dict):
        """
        Writes a single alert record to the log file.

        :param alert: Alert dictionary with keys:
                        mac, count, threshold, window, reason_code, timestamp.
        """
        readable_time = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(alert["timestamp"])
        )

        line = (
            f"[{readable_time}] FLOOD | "
            f"MAC: {alert['mac']} | "
            f"Count: {alert['count']} in {alert['window']}s | "
            f"Reason Code: {alert['reason_code']}\n"
        )

        self._append(line)

    def _append(self, text: str):
        """
        Appends text to the log file.

        Opens and closes the file on every write to ensure data is flushed to disk
        immediately, no log entries are lost if the detector crashes or is interrupted.

        :param text: The text string to append.
        """
        try:
            with open(self.log_file, "a") as f:
                f.write(text)
        except IOError as e:
            print(f"[LOG] Could not write to log file: {e}")