import imaplib
import email
from email.header import decode_header
import time

def connect_to_email(username, password, server='imap.gmail.com'):
    mail = imaplib.IMAP4_SSL(server)
    mail.login(username, password)
    return mail

def mark_unread_as_read(mail):
    try:
        mail.select("inbox")
        status, messages = mail.search(None, 'UNSEEN')
        if status == 'OK':
            for num in messages[0].split():
                mail.store(num, '+FLAGS', '\\Seen')
    except Exception as e:
        print(f"Error marking unread emails as read: {e}")

def fetch_new_emails(mail):
    try:
        mail.select("inbox")
        status, messages = mail.search(None, 'UNSEEN')
        if status == 'OK':
            for num in messages[0].split():
                _, msg_data = mail.fetch(num, '(RFC822)')
                msg = email.message_from_bytes(msg_data[0][1])
                subject, encoding = decode_header(msg['Subject'])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else 'utf-8')
                body = get_email_body(msg)
                print(f'Subject: {subject}')
                print(f'Body: {body}')
    except Exception as e:
        print(f"Error fetching new emails: {e}")

def get_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode()
    else:
        return msg.get_payload(decode=True).decode()

def main(username, password):
    try:
        mail = connect_to_email(username, password)
        mark_unread_as_read(mail)
        while True:
            fetch_new_emails(mail)
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopping the email checker.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        mail.logout()

if __name__ == "__main__":
    main('email@gmail.com', 'app_password')
