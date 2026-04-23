"""
============================================================================
main.py - Deauth Flood Detector
============================================================================
Entry point for the Wi-Fi Deauthentication Flood Detector.

Run with:
    sudo python3 main.py --iface wlan1mon.

Requirements:
    - Raspberry Pi OS with Alfa AWUS036ACM adapter in monitor mode.
    - Kali Linux VM for running the attack simulator (demo only).
    - sudo / root privileges (required for raw packet capture).

Install dependencies:
    pip install scapy paho-mqtt

Enable monitor mode before running:
    sudo airmon-ng start wlan1
    (this usually creates an interface called wlan1mon).
============================================================================
"""

import argparse
import sys

from detector import DeauthDetector
from config import Config

def parse_args():
    """
    Parse command-line arguments so the program can be configured without editing
    source code every time.
    """
    parser = argparse.ArgumentParser(
        description="Wi-Fi Deauthentication Flood Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
            sudo python3 main.py --iface wlan1mon
            sudo python3 main.py --iface wlan1mon --threshold 20 --window 3
        """
    )

    # ===== Network Interface =====
    parser.add_argument(
        "--iface",
        type=str,
        default=None,       # wlan1 = Wi-Fi adapter (wlan0 = built in, reserve for ssh purposes)
        help="Monitor mode interface to listen on (default: wlan1mon)"
    )

    # ===== Detection Tuning =====
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Deauth frames per MAC to trigger alert (default: 10)"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=None,
        help="Rolling time window in seconds (default: 5)"
    )

    # ===== MQTT alerting =====
    parser.add_argument(
        "--mqtt-host",
        type=str,
        default=None,
        help="MQTT broker hostname (default: localhost)"
    )
    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=None,
        help="MQTT broker port (default: 1883)"
    )
    parser.add_argument(
        "--mqtt-topic",
        type=str,
        default=None,
        help="MQTT topic to publish alerts (default: deauth/alerts)"
    )

    # ===== Logging =====
    parser.add_argument(
        "--logfile",
        type=str,
        default=None,
        help="Path to alert log file (default: deauth_alerts.log)"
    )

    return parser.parse_args()

def main():
    """
    Main entry point:
        Parse arguments, builds config, starts detector, and handles a shutdown.
    """
    args = parse_args()

    # Build config, only passes the values explicitly provided.
    # Config handles all default for anything left as None.
    config = Config(
        iface=args.iface,
        threshold=args.threshold,
        time_window=args.window,
        mqtt_host=args.mqtt_host,
        mqtt_port=args.mqtt_port,
        mqtt_topic=args.mqtt_topic,
        log_file=args.logfile
    )

    # Print the startup banner so the user can confirm settings.
    print("=" * 60)
    print("   Wi-Fi Deauth Flood Detector")
    print("=" * 60)
    print(f"   Interface   : {config.iface}")
    print(f"   Threshold   : {config.threshold} frames / {config.time_window}s window")
    print(f"   MQTT        : Enabled ---> {config.mqtt_host}")
    print(f"   Log file    : {config.log_file}")
    print("=" * 60)
    print("   Listening for deauth frames...   (Ctrl+C to stop)\n")

    # Instantiate and start the detector.
    detector = DeauthDetector(config)

    try:
        detector.start()
    except KeyboardInterrupt:
        # Shutdown on Ctrl+C
        print("\n\n[INFO] Stopped by user.")
        detector.print_summary()
        sys.exit(0)


if __name__ == "__main__":
    main()
