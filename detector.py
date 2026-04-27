"""
============================================================================
detector.py - Core Detection Engine
============================================================================
Central detection module responsible for:
    1. Opens a Scapy sniffer on the monitor mode interface.
    2. Filters 802.11 Deauthentication frames.
    3. Tracks frame counts per source MAC address in a rolling time window.
    4. Fires an alert when the count crosses the pre-determined threshold.

802.11 Frame Type Reference:
    - Type 0 = Management frame.
    - Subtype 12 (0xC) = Deauthentication.

Scapy collects raw 802.11 frames at the byte level, allowing direct access to
fields such as MAC addresses and frame subtypes.
============================================================================
"""
import time
from collections import defaultdict
from logger import Logger

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Deauth


class DeauthDetector:
    """
    Captures 802.11 frames and detects deauthentication floods.

    The detection algorithm uses a rolling time window:
    - For each source MAC address, a list of timestamps of every
      deauth frame are stored.
    - On each new frame the timestamp older than the "time_window"
      seconds is pruned from the list.
    - If remaining counts exceeds the "threshold" an alert is sent.
    """

    def __init__(self, config):
        """
        Initialize the detector with a Config object.

        :param config: Runtime configuration (interface, threshold, etc.)
        """
        self.config = config

        # defaultdict(list) means accessing a new MAC key automatically
        # initializes to an empty list.
        # Structure: { "aa:bb:cc:dd:ee:ff": [timestamp1, timestamp2, ...]}
        self.frame_counts = defaultdict(list)

        # Track what MACs have already triggered an alarm to avoid spamming alerts.
        # Structure: { "aa:bb:cc:dd:ee:ff": last_alert_timestamp}
        self.alerted_macs ={}

        # Cooldown period (seconds) before re-alerting the same MAC.
        # Prevents spamming if the flood continues for a long period of time.
        self.alert_cooldown = 45

        # Total counter for the summary.
        self.total_frames_seen = 0
        self.total_alerts_fired = 0

        # Alert manager (terminal + MQTT).
        # TODO: Implement the Alert Manager.
        #self.alert_manager = AlertManager(config)

        # Logger
        self.logger = Logger(config.log_file)

    def start(self):
        """
        Begin packet capture using Scapy's sniff().
        sniff() is a blocking call, will run until manually interrupted.

        Key parameters:
            iface   : Monitor-mode interface to listen on.
            prn     : Callback function called for every captured packet.
            store   : False, don't store packets in memory.
            filter  : "type mgt" limits capture to 802.11 management frames only.
        """
        sniff(
            iface = self.config.iface,
            prn   = self._process_packet,
            store = False,
            filter= "type mgt"
        )

    def _process_packet(self, pkt):
        """
        Callback invoked by Scapy for every captured packet.

        :param pkt: Scapy packet object representing one captured frame.
        """
        self.total_frames_seen += 1

        # Check if the packet has a Deauth layer, Scapy parses 802.11 frames
        # into layered objects:
        #   Dot11       = base 802.11 header
        #   Dot11Deauth = deauthentication fields (reason code, etc)
        # haslayer() returns True only if the subtype is present.
        if not pkt.haslayer(Dot11Deauth):
            return      # Not a deauth frame.

        # Get the source MAC address from the header.
        # pkt[Dot11].addr2 = source address in the 802.11 frame.
        # addr1 = dest, addr2 = source, addr3 = BSSID.
        src_mac = pkt[Dot11].addr2

        if not src_mac:
            return      # Corrupted frame with no source MAC.

        # Reason Code:
        #   - 1(Unspecified): Used when the AP doesn't know what went wrong.
        #   - 2(Previous Auth Invalid): Client is associated but not authorized.
        #   - 3(STA Leaving): Station(client) is leaving the network.
        #   - 4(Disassociated due to Inactivity): Client session timeout.
        #   - 6(Class 2 Frame from Nonauth): Client tried to send data before authentication.
        #   - 7(Class 3 Frame from Nonassoc): Client sent data before association (most common for forcing reconnects).
        #   - 8(STA Leaving BSS): Station is leaving the BSS.
        reason_code = pkt[Dot11Deauth].reason

        # Record current timestamp.
        now = time.time()
        self.frame_counts[src_mac].append(now)

        # Prune timestamp outside the time window.
        cutoff = now - self.config.time_window
        new_list = []
        for t in self.frame_counts[src_mac]:
            if t > cutoff:
                new_list.append(t)
        self.frame_counts[src_mac] = new_list

        # Count how many frames remain in the time window for this MAC.
        count = len(self.frame_counts[src_mac])

        # Debugging statement.
        print(
            f"[FRAME] Deauth from {src_mac} | "
            f"Count in window: {count}/{self.config.threshold} | "
            f"Reason: {reason_code}"
        )

        # Check if the threshold has been crossed.
        if count >= self.config.threshold:
            self._handle_flood(src_mac, count, reason_code, now)

    def _handle_flood(self, src_mac, count, reason_code, timestamp):
        """
        Called when a deauth flood is detected for any given MAC address.

        Implements a cooldown period to prevent alert spamming for the same MAC
        during an ongoing flood - the alert is sent once, then again after the
        cooldown period expires if the flood continues.

        :param src_mac:     Source MAC address of the flooding device.
        :param count:       Number of frames seen in the current window.
        :param reason_code: 802.11 deauth reason code from the frame.
        :param timestamp:   Unix timestamp of when the flood was detected.
        """
        # Check cooldown.
        if src_mac in self.alerted_macs:
            last_alert = self.alerted_macs[src_mac]
        else:
            last_alert = 0

        if timestamp - last_alert < self.alert_cooldown:
            return          # Still in cooldown period.

        # Record this alert timestamp for future cooldowns.
        self.alerted_macs[src_mac] = timestamp
        self.total_alerts_fired += 1

        # Structured alert dictionary to pass to output modules.
        alert = {
            "mac":          src_mac,
            "count":        count,
            "threshold":    self.config.threshold,
            "window":       self.config.time_window,
            "reason_code":  reason_code,
            "timestamp":    timestamp,
        }

        # Send the alert through all configured output channels.
        #self.alert_manager.send(alert)

        # Write the alert to the log file.
        self.logger.log(alert)

    def print_summary(self):
        """
        Print a summary of the detection activity.
        Called when the user presses Ctrl+C to stop the detector.
        """
        print("\n" + "=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        print(f"  Total frames captured     : {self.total_frames_seen}")
        print(f"  Total flood alerts fired  : {self.total_alerts_fired}")

        if self.alerted_macs:
            print(f"\n  MACs that triggered alerts:")
            for mac, ts in self.alerted_macs.items():
                readable_time = time.strftime("%H:%M:%S", time.localtime(ts))
                print(f"    {mac}   (last alert at {readable_time})")
        else:
            print("\n  No floods detected.")

        print("=" * 60)