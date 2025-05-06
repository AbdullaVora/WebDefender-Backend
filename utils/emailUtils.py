# utils/email.py
from aiosmtplib import send
from email.message import EmailMessage

async def send_email(recipient: str, subject: str, body: str):
    message = EmailMessage()
    message["From"] = "webScanner@gmail.com"
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    await send(
        message,
        hostname="smtp.gmail.com",
        port=465,
        username="blackmask8866@gmail.com",
        password="rkou eeji qugd enbr",
        use_tls=True,
    )
