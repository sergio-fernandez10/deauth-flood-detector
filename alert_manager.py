"""
alert_manager.py
----------------
Alert manager for the deauth attack detector.
Sends SMS via email-to-SMS gateways — no third-party accounts,
no registration, no cost.

Supported carriers:   att, tmobile, verizon, sprint, boost, cricket, uscellular
Supported email:      Gmail, Outlook/Hotmail, Yahoo (see SMTP_PROVIDERS below)

Setup:
    Run setup.py first — it walks you through configuration interactively.
    Or manually create config.env with:

        EMAIL_ADDRESS=you@gmail.com
        EMAIL_PASSWORD=your_app_password
        EMAIL_PROVIDER=gmail
        PHONE_NUMBER=5550001234
        CARRIER=verizon

Requirements:
    pip install python-dotenv
"""

import os
import smtplib
import logging
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / "config.env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Carrier SMS gateways
# ---------------------------------------------------------------------------
CARRIERS = {
    "att":        "txt.att.net",
    "tmobile":    "tmomail.net",
    "verizon":    "vtext.com",
    "sprint":     "messaging.sprintpcs.com",
    "boost":      "sms.myboostmobile.com",
    "cricket":    "sms.cricketwireless.net",
    "uscellular": "email.uscc.net",
}

# ---------------------------------------------------------------------------
# SMTP provider settings
# ---------------------------------------------------------------------------
SMTP_PROVIDERS = {
    "gmail": {
        "host": "smtp.gmail.com",
        "port": 587,
        "note": "Requires a Gmail App Password (not your regular password). "
                "Enable at myaccount.google.com > Security > App Passwords.",
    },
    "outlook": {
        "host": "smtp.office365.com",
        "port": 587,
        "note": "Use your regular Outlook password, or an app password if "
                "you have 2FA enabled.",
    },
    "yahoo": {
        "host": "smtp.mail.yahoo.com",
        "port": 587,
        "note": "Requires a Yahoo App Password. "
                "Enable at myaccount.yahoo.com > Security > App Passwords.",
    },
}


class AlertManager:
    """
    Sends SMS alerts via email-to-SMS gateways.

    Reads configuration from config.env by default.
    All parameters can be overridden directly for testing.

    Usage:
        manager = AlertManager()
        manager.send_alert("Deauth attack detected on BSSID AA:BB:CC:DD:EE:FF")
    """

    def __init__(
        self,
        email_address: str  = None,
        email_password: str = None,
        email_provider: str = None,
        phone_number: str   = None,
        carrier: str        = None,
    ):
        self.email_address  = email_address     or os.getenv("EMAIL_ADDRESS")
        self.email_password = email_password    or os.getenv("EMAIL_PASSWORD")
        self.email_provider = (email_provider   or os.getenv("EMAIL_PROVIDER", "")).lower()
        self.phone_number   = phone_number      or os.getenv("PHONE_NUMBER")
        self.carrier        = (carrier          or os.getenv("CARRIER", "")).lower()

        self._validate()

        self.smtp_config = SMTP_PROVIDERS[self.email_provider]
        self.gateway     = CARRIERS[self.carrier]
        self.digits      = "".join(filter(str.isdigit, self.phone_number))

        logger.info("AlertManager ready.")

    def _validate(self):
        missing = []
        if not self.email_address:  missing.append("EMAIL_ADDRESS")
        if not self.email_password: missing.append("EMAIL_PASSWORD")
        if not self.phone_number:   missing.append("PHONE_NUMBER")

        if missing:
            raise EnvironmentError(
                f"Missing config: {', '.join(missing)}. "
                "Run setup.py or check your config.env."
            )

        if self.email_provider not in SMTP_PROVIDERS:
            raise EnvironmentError(
                f"Unknown email provider '{self.email_provider}'. "
                f"Choose from: {', '.join(SMTP_PROVIDERS)}"
            )

        if self.carrier not in CARRIERS:
            raise EnvironmentError(
                f"Unknown carrier '{self.carrier}'. "
                f"Choose from: {', '.join(CARRIERS)}"
            )

        digits = "".join(filter(str.isdigit, self.phone_number))
        if len(digits) != 10:
            raise ValueError(
                f"Phone number must be 10 digits, got '{self.phone_number}'. "
                "Do not include the country code."
            )

    def send_alert(self, message: str, phone_number: str = None) -> bool:
        """
        Send an SMS alert.

        Args:
            message:      The alert text.
            phone_number: Override the number in config.env (10 digits, optional).

        Returns:
            True on success, False on failure.
        """
        if phone_number:
            digits = "".join(filter(str.isdigit, phone_number))
            if len(digits) != 10:
                logger.error("Override phone number must be 10 digits: %s", phone_number)
                return False
        else:
            digits = self.digits

        to_address = f"{digits}@{self.gateway}"
        body = (
            f"[DEAUTH ALERT]\n"
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"{message}"
        )

        msg = MIMEText(body)
        msg["From"]    = self.email_address
        msg["To"]      = to_address
        msg["Subject"] = "Deauth Alert"

        try:
            with smtplib.SMTP(self.smtp_config["host"], self.smtp_config["port"]) as server:
                server.ehlo()
                server.starttls()
                server.login(self.email_address, self.email_password)
                server.sendmail(self.email_address, to_address, msg.as_string())

            logger.info("Alert sent → %s", to_address)
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error(
                "Authentication failed for %s. %s",
                self.email_address,
                self.smtp_config["note"],
            )
            return False

        except smtplib.SMTPException as e:
            logger.error("SMTP error: %s", e)
            return False

        except Exception as e:
            logger.error("Unexpected error: %s", e)
            return False

    def send(self, alert: dict) -> bool:
        """
        Adapter method for integration with detector.py.
        Formats the alert dict into a readable SMS message.

        :param alert: Alert dictionary with keys:
                      mac, counter, window, reason_code.
        """
        message = (
            f"Flood detected!\n"
            f"MAC: {alert['mac']}\n"
            f"Count: {alert['count']} frames in {alert['window']}s\n"
            f"Reason Code: {alert['reason_code']}"
        )
        return self.send_alert(message)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def send_alert(message: str) -> bool:
    """Send an alert using settings from config.env."""
    return AlertManager().send_alert(message)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    success = send_alert("Smoke test — alert manager is working.")
    sys.exit(0 if success else 1)
