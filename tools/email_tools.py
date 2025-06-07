# D:\email-agent\tools\email_tools.py (PRODUCTION-READY VERSION)

import os
import pickle
import json
import base64
import pandas as pd
from email.mime.text import MIMEText
from base64 import urlsafe_b64encode

from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials # Import Credentials class

import streamlit as st

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def get_gmail_service():
    creds = None

    # Load credentials from Streamlit secrets
    try:
        # Decode the base64 token
        token_pickle_bytes = base64.b64decode(st.secrets["google_token_pickle_base64"])
        creds = pickle.loads(token_pickle_bytes)
        st.success("Token loaded from secrets.")
    except Exception as e:
        st.error(f"Failed to decode or unpickle token from secrets: {e}. Will attempt re-authentication.")
        creds = None # Reset creds if loading fails

    # If token is expired or invalid, refresh it
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            st.info("Token refreshed successfully using secrets.")
            # Update the token in secrets if refreshed (optional, but good practice if you can write back)
            # Note: Streamlit secrets are read-only at runtime. This won't actually save to secrets.toml
            # It's primarily for local testing if you were to manage it differently.
            # For Streamlit Cloud, you'd manually update the secret after a refresh.
        except Exception as e:
            st.error(f"Error refreshing expired token from secrets: {e}. Authentication required again.")
            creds = None

    # If no valid creds (first run or refresh failed), attempt to build from client secrets JSON
    # This path is primarily for initial setup / if refresh token isn't present
    if not creds or not creds.valid:
        try:
            # Parse the JSON string from secrets
            client_secrets_json = json.loads(st.secrets["google_credentials_json"])

            # Create credentials object from client secrets
            creds = Credentials.from_authorized_user_info(
                info=client_secrets_json["web"], # Use the "web" part of the JSON
                scopes=SCOPES
            )
            # Note: For production, you generally expect `google_token_pickle_base64` to be present and valid.
            # This block here is a fallback for *very* initial setup or if a refresh token is somehow missing.
            # For robust refresh, the token should have been created with offline access.

            st.success("Credentials loaded from `google_credentials_json` in secrets.")
            # You might want to remove this line after successful initial setup to avoid confusion
            # as the primary goal is to use the token.pickle for subsequent runs.

        except Exception as e:
            st.error(f"Error: `google_credentials_json` secret is not valid JSON or could not be used: {e}")
            st.error("Gmail authentication failed. Check your credentials (e.g., credentials.json or secrets).")
            return None

    if creds:
        try:
            service = build('gmail', 'v1', credentials=creds)
            return service
        except Exception as e:
            st.error(f"Error building Gmail service after authentication: {e}")
            return None
    return None

# Keep your read_recipients_from_excel and send_gmail_message functions below them unchanged
def send_gmail_message(service, user_id, to, subject, message_text):
    """
    Sends a Gmail message.
    ... (your existing code for send_gmail_message) ...
    """
    try:
        message = MIMEText(message_text)
        message['to'] = to
        message['from'] = user_id
        message['subject'] = subject

        raw_message = urlsafe_b64encode(message.as_bytes()).decode()
        body = {'raw': raw_message}

        message_sent = (service.users().messages().send(userId=user_id, body=body)
                       .execute())
        st.info(f"Message sent to {to}. ID: {message_sent['id']}")
        return True
    except Exception as e:
        st.error(f"An error occurred while sending email to {to}: {e}")
        return False

def read_recipients_from_excel(file_path):
    """
    Reads recipient emails from an Excel file.
    ... (your existing code for read_recipients_from_excel) ...
    """
    try:
        df = pd.read_excel(file_path)
        email_col = None
        for col in df.columns:
            if col.lower() == 'email':
                email_col = col
                break

        if email_col is None:
            st.warning("Error: 'Email' column not found in the Excel file. Please ensure your Excel file has an 'Email' column.")
            return []

        recipients = df[email_col].dropna().apply(lambda x: {'email': str(x).strip()}).tolist()

        if not recipients:
            st.info("No valid email addresses found in the 'Email' column of the Excel file.")

        return recipients
    except FileNotFoundError:
        st.error(f"Error: Excel file not found at '{file_path}'. Please upload the correct file.")
        return []
    except Exception as e:
        st.error(f"Error reading recipients from Excel: {e}")
        return []
