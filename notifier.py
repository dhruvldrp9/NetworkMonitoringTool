import requests
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self):
        # Email configuration
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.email_from = os.getenv('EMAIL_FROM', '')
        self.email_password = os.getenv('EMAIL_PASSWORD', '')
        
        # SMS configuration (using Twilio)
        self.twilio_sid = os.getenv('TWILIO_ACCOUNT_SID', '')
        self.twilio_token = os.getenv('TWILIO_AUTH_TOKEN', '')
        self.twilio_phone = os.getenv('TWILIO_PHONE_NUMBER', '')
        
        # Webhook configuration
        self.webhook_urls = os.getenv('WEBHOOK_URLS', '').split(',')
        
        # Initialize notification channels
        self.channels = {
            'email': self.send_email_alert,
            'sms': self.send_sms_alert,
            'webhook': self.send_webhook_alert
        }

    def send_alert(self, threat_info, channels=None):
        """Send alert through specified channels"""
        if channels is None:
            channels = ['webhook']  # Default to webhook
        
        for channel in channels:
            if channel in self.channels:
                try:
                    self.channels[channel](threat_info)
                except Exception as e:
                    logger.error(f"Failed to send {channel} alert: {e}")

    def send_email_alert(self, threat_info):
        """Send email alert"""
        if not all([self.email_from, self.email_password]):
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_from
            msg['To'] = self.email_from  # Send to self for now
            msg['Subject'] = f"Security Alert: {threat_info['type']}"
            
            body = f"""
            Security Threat Detected:
            Type: {threat_info['type']}
            Source: {threat_info['source']}
            Severity: {threat_info.get('severity', 'unknown')}
            Details: {threat_info['details']}
            Time: {threat_info.get('timestamp', 'N/A')}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_from, self.email_password)
                server.send_message(msg)
                
            logger.info("Email alert sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    def send_sms_alert(self, threat_info):
        """Send SMS alert using Twilio"""
        if not all([self.twilio_sid, self.twilio_token, self.twilio_phone]):
            return
            
        try:
            from twilio.rest import Client
            client = Client(self.twilio_sid, self.twilio_token)
            
            message = f"""
            Security Alert!
            Type: {threat_info['type']}
            Source: {threat_info['source']}
            Severity: {threat_info.get('severity', 'unknown')}
            """
            
            client.messages.create(
                body=message,
                from_=self.twilio_phone,
                to=os.getenv('ALERT_PHONE_NUMBER', '')
            )
            
            logger.info("SMS alert sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send SMS alert: {e}")

    def send_webhook_alert(self, threat_info):
        """Send webhook alert"""
        if not self.webhook_urls:
            return
            
        for url in self.webhook_urls:
            if not url:
                continue
                
            try:
                response = requests.post(
                    url.strip(),
                    json=threat_info,
                    headers={'Content-Type': 'application/json'}
                )
                response.raise_for_status()
                logger.info(f"Webhook alert sent successfully to {url}")
                
            except Exception as e:
                logger.error(f"Failed to send webhook alert to {url}: {e}")
