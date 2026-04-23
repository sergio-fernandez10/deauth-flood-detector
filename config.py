"""
=============================================================================
config.py — Centralized Configuration
=============================================================================
"""

class Config:
    """
    Runtime configuration for the Deauth Flood Detector.

    Attributes:
        iface       : Network interface in monitor mode.
        threshold   : Number of deauth frames from one MAC within the time
                      window to trigger an alert.
                       - Too low: false positives.
                       - Too high: missed floods.
        time_window : Rolling time window in seconds for counting frames per MAC,
        mqtt_enabled: Whether to publish alerts to a MQTT broker.
        mqtt_host   : Hostname or IP of the MQTT broker.
        mqtt_port   : Port for the MQTT broker (default 1883 for unencrypted).
        mqtt_topic  : Topic string to publish alert messages on.
        log_file    : Path to the alert log file.
    """

    def __init__(
        self,
        iface=None,
        threshold=None,
        time_window=None,
        mqtt_enabled=True,
        mqtt_host=None,
        mqtt_port=None,
        mqtt_topic=None,
        log_file=None,
    ):
        self.iface          = iface             or "wlan1mon"
        self.threshold      = threshold         or 10
        self.time_window    = time_window       or 5
        self.mqtt_enabled   = mqtt_enabled
        self.mqtt_host      = mqtt_host         or "localhost"
        self.mqtt_port      = mqtt_port         or 1883
        self.mqtt_topic     = mqtt_topic        or "deauth/alerts"
        self.log_file       = log_file          or "deauth_alerts.log"