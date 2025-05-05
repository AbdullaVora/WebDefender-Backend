# utils/email.py
from typing import Optional
import logging
from fastapi import BackgroundTasks

logger = logging.getLogger(__name__)

async def send_email(
    recipient: str,
    subject: str,
    body: str,
    background_tasks: Optional[BackgroundTasks] = None
):
    """Mock email sender that just logs messages"""
    email_content = f"""
    To: {recipient}
    Subject: {subject}
    Body: {body}
    """
    
    logger.info(f"Mock email sent:\n{email_content}")
    
    # Store in memory (for testing verification)
    if not hasattr(send_email, "sent_emails"):
        send_email.sent_emails = []
    send_email.sent_emails.append({
        "recipient": recipient,
        "subject": subject,
        "body": body
    })

# For testing
def get_last_email():
    return send_email.sent_emails[-1] if getattr(send_email, "sent_emails", None) else None