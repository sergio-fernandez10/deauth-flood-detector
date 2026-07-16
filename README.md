# Deauth Flood Detector

A Wi-Fi deauthentication flood detector for wireless networks, built in Python with Scapy.

## Team Members

**Sergio**

* Monitor mode setup and configuration of the Alfa adapter.
* Core Scapy frame capture and parsing.
* Live demo setup and testing.
* Logging system and persistent alert log writer.
* Runtime configuration handling.
* Deauth-injection test simulator used for the live demo.

**Nick Porter**

* Threshold engine, rate counter, and alert logic.
* Result analysis: latency measurements and false positive testing.
* SMS alerting system (email-to-SMS gateway logic and interactive setup wizard).

## Project Description

This tool monitors 802.11 traffic in monitor mode and watches for deauthentication ("deauth") floods — a common Wi-Fi attack where an attacker repeatedly sends deauth frames to force clients off a network. It sniffs management frames, isolates deauthentication frames per source MAC address, and tracks how many arrive within a rolling time window. When one MAC address crosses a configurable threshold, it fires an alert, logs the event, and can notify you directly via SMS.

## ⚠️ Legal & Ethical Use

This repository includes `simulator.py`, a script that actively injects 802.11 deauthentication frames — the same technique used in real Wi-Fi deauth attacks.

**Only run the simulator against networks and devices you own, or have explicit written permission to test.** Injecting deauth frames at a network you don't control or lack authorization for is illegal in most jurisdictions (e.g. under the U.S. Computer Fraud and Abuse Act and FCC regulations on intentional wireless interference) and can carry serious civil and criminal penalties, regardless of intent.

The simulator is provided strictly for educational use and for testing this detector — for example, against your own phone's hotspot. If you're unsure whether you're authorized to test a given network, don't.

## Features

* **Live 802.11 monitoring** — uses Scapy to sniff management frames on a monitor-mode wireless interface.
* **Per-MAC flood detection** — tracks deauth frame timestamps per source MAC in a rolling time window, so bursts from one device are distinguished from normal background noise.
* **Configurable threshold and window** — tune sensitivity via `--threshold` and `--window` flags to balance false positives against missed floods.
* **Alert cooldown** — once a MAC triggers an alert, it won't re-alert for a configurable cooldown period, preventing alert spam during an ongoing flood.
* **Persistent logging** — every flood event is appended to a log file with timestamp, MAC, frame count, and 802.11 reason code, and sessions are clearly separated for later review.
* **SMS alerting via email-to-SMS gateways** — sends alerts straight to your phone using free carrier email-to-SMS gateways (AT&T, T-Mobile, Verizon, Sprint, Boost, Cricket, US Cellular), authenticated through Gmail, Outlook, or Yahoo SMTP — no third-party SMS service or account required.
* **Interactive setup wizard** (`setup.py`) — walks through selecting an email provider and carrier, validates SMTP login, sends a live test SMS, and saves the result to `config.env`.
* **End-of-run summary** — prints total frames captured, total alerts fired, and which MACs triggered them when the detector is stopped.
* **Built-in test simulator** (`simulator.py`) — a companion script that injects deauth frames on a network you own or have permission to test, so you can watch the detector fire in real time during a demo. Includes explicit legal/ethical-use guidance in the file itself, and is intended only for testing this detector.

## Requirements

* Detector: Raspberry Pi OS, with a wireless adapter capable of monitor mode (developed and tested with an Alfa AWUS036ACM)
* A monitor-mode interface already enabled, e.g.:
  ```bash
  sudo airmon-ng start wlan1
  ```
  (this typically creates an interface named `wlan1mon`)
* Python 3 with:
  ```bash
  pip install scapy python-dotenv
  ```
* Root/sudo privileges (required for raw packet capture)

## Setup

To enable SMS alerts, run the interactive setup wizard once:

```bash
python setup.py
```

This configures `config.env` with your email provider, carrier, and phone number, and sends a test SMS to confirm everything works. Alerts can also be configured manually by editing `config.env` directly.

## Usage

```bash
sudo python3 main.py --iface wlan1mon
```

**Options:**

* `--iface` — monitor-mode interface to listen on (default: `wlan1mon`).
* `--threshold` — number of deauth frames from one MAC required to trigger an alert (default: 10).
* `--window` — rolling time window in seconds for counting frames per MAC (default: 5).
* `--mqtt-host`, `--mqtt-port`, `--mqtt-topic` — MQTT broker settings for publishing alerts (defaults: `localhost`, `1883`, `deauth/alerts`).
* `--logfile` — path to the alert log file (default: `deauth_alerts.log`).

**Example:**

```bash
sudo python3 main.py --iface wlan1mon --threshold 20 --window 3
```

## Testing / Demo

`simulator.py` is a companion script that plays the "attacker" role for testing the detector — it crafts and injects 802.11 deauth frames so you can watch the detector fire in real time. Run the detector in one terminal and the simulator in another. **See [Legal & Ethical Use](#️-legal--ethical-use) above before running this.**

```bash
sudo python3 simulator.py --iface wlan0mon --target FF:FF:FF:FF:FF:FF --count 50
```

**Options:**

* `--iface` — monitor-mode interface to inject frames on (default: `wlan0mon`).
* `--target` — destination MAC address to deauth; defaults to the broadcast address (`FF:FF:FF:FF:FF:FF`), which affects all devices on the network. Replace with a specific MAC to target a single device.
* `--bssid` — BSSID (access point MAC) to spoof as the sender; a random MAC is generated if not specified.
* `--count` — number of deauth frames to send (default: 30).
* `--interval` — seconds between frames (default: 0.1, i.e. 10 frames/sec).
* `--flood` — send frames as fast as possible, ignoring `--interval`.
* `--reason` — 802.11 deauth reason code to include in frames (default: 1, "Unspecified").

## Project Status

**In development.** Core detection, logging, and SMS alerting are functional and connected end-to-end. MQTT alert publishing is defined in configuration but not yet wired into the alert pipeline.
