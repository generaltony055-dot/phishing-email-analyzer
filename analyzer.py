from email import policy
from email.parser import BytesParser
import re
from urllib.parse import urlparse


def extract_urls(text):
    pattern = r'https?://[^\s]+'
    return re.findall(pattern, text)


def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    reasons = []

    if "@" in url:
        reasons.append("URL contains @ symbol")

    if len(url) > 100:
        reasons.append("Very long URL")

    if "-" in domain:
        reasons.append("Domain contains a hyphen")

    return {
        "url": url,
        "domain": domain,
        "suspicious": len(reasons) > 0,
        "reasons": reasons
    }


def detect_urgent_language(text):
    suspicious_words = [
        "urgent",
        "immediately",
        "verify",
        "suspended",
        "password",
        "account locked",
        "click here",
        "confirm your account"
    ]

    text = text.lower()

    found = []

    for word in suspicious_words:
        if word in text:
            found.append(word)

    return found


def parse_email(file_path):
    with open(file_path, "rb") as f:
        email_message = BytesParser(
            policy=policy.default
        ).parse(f)

    sender = email_message.get("From")
    recipient = email_message.get("To")
    subject = email_message.get("Subject")
    date = email_message.get("Date")

    body = ""

    if email_message.is_multipart():
        for part in email_message.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = email_message.get_content()

    urls = extract_urls(body)

    body_and_subject = body + " " + (subject or "")

    return {
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "date": date,
        "body": body_and_subject,
        "urls": urls
    }


def calculate_risk(url_results, urgent_words, sender_analysis):
    score = 0
    reasons = []

    # URL detection
    for result in url_results:
        if result["suspicious"]:
            score += 30

            for reason in result["reasons"]:
                reasons.append(reason)

    # Urgent language detection
    if urgent_words:
        score += 20
        reasons.append("Urgent or suspicious language detected")

    # Sender detection
    if sender_analysis["suspicious"]:
        score += 30
        reasons.append("Suspicious sender detected")

        for reason in sender_analysis["reasons"]:
            reasons.append(reason)

    # Risk level
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, reasons


def analyze_sender(sender):
    reasons = []

    if not sender:
        return {
            "suspicious": True,
            "reasons": ["Sender address is missing"]
        }

    sender = sender.lower()

    if "@" not in sender:
        reasons.append("Invalid sender address")
    else:
        domain = sender.split("@")[-1]

        suspicious_domains = [
            "example.com",
            "test.com",
            "fake.com"
        ]

        if domain in suspicious_domains:
            reasons.append("Sender uses a suspicious/test domain")

    return {
        "suspicious": len(reasons) > 0,
        "reasons": reasons
    }
