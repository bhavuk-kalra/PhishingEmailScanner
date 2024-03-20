import imaplib
import email
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
from google.oauth2 import service_account


# Gmail OAuth 2.0 Settings
SCOPES = ['https://mail.google.com/']
SERVICE_ACCOUNT_FILE = 'path to json client file'
IMAP_USERNAME = 'enter username'

# IMAP Settings for Gmail
IMAP_SERVER = 'imap.gmail.com'

# VirusTotal API Settings
VIRUSTOTAL_API_KEY = 'your virus total api key'
VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'

# Function to create Gmail service object using OAuth 2.0
def create_gmail_service():
    credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    delegated_credentials = credentials.with_subject(IMAP_USERNAME)
    service = imaplib.IMAP4_SSL(IMAP_SERVER)
    service.authenticate('XOAUTH2', lambda x: delegated_credentials.token)
    return service

# Function to scan URL using VirusTotal API
def scan_url(url):
    params = {'apikey': VIRUSTOTAL_API_KEY, 'url': url}
    response = requests.post(VIRUSTOTAL_SCAN_URL, data=params)
    result = response.json()
    return result

# Function to move email to spam folder
def move_to_spam(email_id, conn):
    conn.select('INBOX') # Select inbox
    result, data = conn.uid('COPY', email_id, 'Spam') # Copy email to spam folder
    if result == 'OK':
        conn.uid('STORE', email_id , '+FLAGS', r'(\Deleted)') # Mark original email as deleted
        conn.expunge() # Permanently remove the email from inbox
        return True
    else:
        return False

# Function to process incoming emails
def process_emails():
    # Connect to Gmail using OAuth 2.0
    imap = create_gmail_service()
    imap.select('inbox')

    # Search for unread emails
    result, data = imap.search(None, 'UNSEEN')
    email_ids = data[0].split()

    for email_id in email_ids:
        # Fetch email data
        result, email_data = imap.fetch(email_id, '(RFC822)')
        raw_email = email_data[0][1]
        msg = email.message_from_bytes(raw_email)

        # Extract URLs from email body
        urls = []
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain' or content_type == 'text/html':
                    body = part.get_payload(decode=True).decode()
                    urls += extract_urls(body)
        else:
            body = msg.get_payload(decode=True).decode()
            urls += extract_urls(body)

        # Scan URLs using VirusTotal
        for url in urls:
            result = scan_url(url)
            if result['response_code'] == 1:
                # URL has been scanned
                positives = result['positives']
                if positives > 0:
                    # URL is malicious, move email to spam folder
                    move_to_spam(email_id, imap)
                else:
                    # URL is safe, continue processing other URLs
                    pass
            else:
                # URL couldn't be scanned
                pass

        # Mark email as read
        imap.store(email_id, '+FLAGS', '\\Seen')

    # Close IMAP connection
    imap.close()
    imap.logout()

# Function to extract URLs from text
def extract_urls(text):
    import re
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
    return urls

# Main function to continuously process emails
def main():
    while True:
        process_emails()
        # Add a delay before checking for new emails again
        # You may adjust the delay according to your requirements
        import time
        time.sleep(60)

if __name__ == '__main__':
    main()
