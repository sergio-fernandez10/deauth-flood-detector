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
        iface="wlan1mon",
        threshold=10,
        time_window=5,
        mqtt_enabled=False,
        mqtt_host="localhost",
        mqtt_port=1883,
        mqtt_topic="deauth/alerts",
        log_file="deauth_alerts.log"
    ):
        self.iface          = iface
        self.threshold      = threshold
        self.time_window    = time_window
        self.mqtt_enabled   = mqtt_enabled
        self.mqtt_host      = mqtt_host
        self.mqtt_port      = mqtt_port
        self.mqtt_topic     = mqtt_topic
        self.log_file       = log_file