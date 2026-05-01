#!/usr/bin/env python3
"""
setup.py
--------
Interactive setup wizard for the deauth alert manager.
Run this once to configure your personal credentials.

Usage:
    python setup.py
"""

import os
import sys
import smtplib
from pathlib import Path
from email.mime.text import MIMEText

CONFIG_FILE = Path(__file__).parent / "config.env"

CARRIERS = {
    "1": ("att",        "AT&T",         "txt.att.net"),
    "2": ("tmobile",    "T-Mobile",     "tmomail.net"),
    "3": ("verizon",    "Verizon",      "vtext.com"),
    "4": ("sprint",     "Sprint",       "messaging.sprintpcs.com"),
    "5": ("boost",      "Boost Mobile", "sms.myboostmobile.com"),
    "6": ("cricket",    "Cricket",      "sms.cricketwireless.net"),
    "7": ("uscellular", "US Cellular",  "email.uscc.net"),
}

SMTP_PROVIDERS = {
    "1": ("gmail",   "Gmail",           "smtp.gmail.com",       587,
          "You need a Gmail App Password — NOT your regular password.\n"
          "  1. Go to myaccount.google.com\n"
          "  2. Security → 2-Step Verification (enable if not on)\n"
          "  3. Security → App Passwords\n"
          "  4. Generate one for 'Mail' and paste it below."),
    "2": ("outlook", "Outlook/Hotmail", "smtp.office365.com",   587,
          "Use your regular Outlook password.\n"
          "  If you have 2FA enabled, generate an app password at\n"
          "  account.microsoft.com > Security > App Passwords."),
    "3": ("yahoo",   "Yahoo Mail",      "smtp.mail.yahoo.com",  587,
          "You need a Yahoo App Password — NOT your regular password.\n"
          "  1. Go to myaccount.yahoo.com\n"
          "  2. Security → App Passwords\n"
          "  3. Generate one and paste it below."),
}


def banner(text):
    print(f"\n{'─' * 50}")
    print(f"  {text}")
    print(f"{'─' * 50}")


def prompt(label, hidden=False):
    import getpass
    if hidden:
        return getpass.getpass(f"  {label}: ").strip()
    value = input(f"  {label}: ").strip()
    return value


def pick_from_menu(title, options: dict):
    print(f"\n{title}")
    for key, values in options.items():
        print(f"  [{key}] {values[1]}")
    while True:
        choice = input("  Enter number: ").strip()
        if choice in options:
            return options[choice]
        print("  Invalid choice, try again.")


def test_smtp(host, port, email, password):
    try:
        with smtplib.SMTP(host, port) as server:
            server.ehlo()
            server.starttls()
            server.login(email, password)
        return True, None
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed — double-check your email and password/app password."
    except Exception as e:
        return False, str(e)


def send_test_sms(host, port, email, password, phone_digits, gateway):
    to_address = f"{phone_digits}@{gateway}"
    msg = MIMEText("Test alert from your deauth detector — setup successful!")
    msg["From"]    = email
    msg["To"]      = to_address
    msg["Subject"] = ""
    try:
        with smtplib.SMTP(host, port) as server:
            server.ehlo()
            server.starttls()
            server.login(email, password)
            server.sendmail(email, to_address, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)


def write_config(email, password, provider_key, phone, carrier_key):
    config = (
        f"EMAIL_ADDRESS={email}\n"
        f"EMAIL_PASSWORD={password}\n"
        f"EMAIL_PROVIDER={provider_key}\n"
        f"PHONE_NUMBER={phone}\n"
        f"CARRIER={carrier_key}\n"
    )
    CONFIG_FILE.write_text(config)
    print(f"\n  ✓ Config saved to {CONFIG_FILE}")


def main():
    banner("Deauth Detector — Alert Manager Setup")
    print("\n  This wizard will configure SMS alerts for your account.")
    print("  Your credentials stay on this machine only.\n")

    # --- Email provider ---
    provider = pick_from_menu("Step 1: Select your email provider", SMTP_PROVIDERS)
    provider_key, provider_name, smtp_host, smtp_port, note = provider

    print(f"\n  Note for {provider_name}:")
    print(f"  {note}\n")

    email    = prompt("Your email address")
    password = prompt("App password (input hidden)", hidden=True)

    print("\n  Testing email credentials...", end=" ", flush=True)
    ok, err = test_smtp(smtp_host, smtp_port, email, password)
    if not ok:
        print(f"FAILED\n\n  Error: {err}")
        print("\n  Fix the issue above and run setup.py again.")
        sys.exit(1)
    print("OK")

    # --- Carrier ---
    carrier = pick_from_menu("\nStep 2: Select your mobile carrier", CARRIERS)
    carrier_key, carrier_name, gateway = carrier

    # --- Phone number ---
    print("\nStep 3: Enter your phone number")
    while True:
        phone = prompt("10-digit phone number (no dashes or spaces)")
        digits = "".join(filter(str.isdigit, phone))
        if len(digits) == 10:
            break
        print("  Must be exactly 10 digits. Do not include country code.")

    # --- Send test SMS ---
    print(f"\n  Sending test SMS to {digits}@{gateway}...", end=" ", flush=True)
    ok, err = send_test_sms(smtp_host, smtp_port, email, password, digits, gateway)
    if not ok:
        print(f"FAILED\n\n  Error: {err}")
        print("\n  Email credentials work but SMS delivery failed.")
        print("  Double-check your carrier selection and phone number.")
        sys.exit(1)
    print("SENT")

    # --- Save config ---
    write_config(email, password, provider_key, digits, carrier_key)

    banner("Setup complete!")
    print("  Check your phone for the test message.")
    print("  If it didn't arrive within 60 seconds, double-check your carrier.\n")
    print("  To use the alert manager in your detector:")
    print("    from alert_manager import send_alert")
    print('    send_alert("Deauth attack detected on BSSID AA:BB:CC:DD:EE:FF")\n')


if __name__ == "__main__":
    main()
