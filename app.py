import streamlit as st
import os
import sys
from typing import List, Dict, Any, Optional

# Assuming 'models' and 'tools' directories are in the same parent directory as app.py
# You might need to adjust sys.path if your project structure is different
# This adjustment is specifically to help Streamlit find your local modules.
# For '/mount/src/email_ai_agent/app.py', the base directory is '/mount/src/email_ai_agent/'
# So, adding this helps in finding 'models.email_models' and 'tools.email_tools'
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir) # Adjust if your structure is different. Assuming app.py is in project_root
sys.path.insert(0, current_dir) # Add current directory to path
# sys.path.insert(0, project_root) # Potentially needed if models/tools are one level up from app.py

# Based on your traceback "/mount/src/email_ai_agent/app.py"
# and the imports "from models.email_models import..." and "from tools.email_tools import..."
# it implies 'models' and 'tools' are subdirectories of 'email_ai_agent'.
# The initial sys.path.append(os.path.dirname(__file__)) I suggested before
# should ideally resolve this if 'app.py' is in the root and 'models' and 'tools' are its direct children.
# Let's refine it slightly to be more robust:
if current_dir not in sys.path:
    sys.path.append(current_dir) # Ensure the directory containing app.py is in the path.

from models.email_models import EmailContext
from tools.email_tools import get_gmail_service, read_recipients_from_excel, send_gmail_message

# Global variable for Gmail service (will be managed with st.session_state)
GMAIL_SERVICE_PERSISTENT = None # Renamed to avoid confusion with local GMAIL_SERVICE

def authenticate_gmail():
    """Authenticates with Gmail and stores the service object."""
    global GMAIL_SERVICE_PERSISTENT
    try:
        st.info("Authenticating with Gmail...")
        service = get_gmail_service() # This function is expected to be blocking or handled by its own async context
        if service:
            GMAIL_SERVICE_PERSISTENT = service
            st.success("Gmail authentication successful!")
            return True
        else:
            st.error("**Gmail authentication failed.** Check your credentials (e.g., `credentials.json` or secrets).")
            return False
    except Exception as e:
        st.error(f"Error during Gmail authentication: {e}")
        st.warning("Ensure `credentials.json` is correctly set up as a Streamlit secret or accessible.")
        return False

def main():
    st.set_page_config(page_title="Streamlit Email Sender", layout="centered")
    st.title("📧 Streamlit Email Sender")

    # Initialize session state variables
    if "email_context" not in st.session_state:
        st.session_state.email_context = EmailContext()
    if "current_email_message" not in st.session_state:
        st.session_state.current_email_message = ""
    if "recipients_list" not in st.session_state:
        st.session_state.recipients_list = []
    if "gmail_service" not in st.session_state:
        st.session_state.gmail_service = None

    # --- Gmail Authentication ---
    # Attempt to authenticate if not already authenticated
    if st.session_state.gmail_service is None:
        st.warning("Gmail service not authenticated. Please authenticate to proceed.")
        if st.button("Authenticate Gmail API"):
            if authenticate_gmail():
                st.session_state.gmail_service = GMAIL_SERVICE_PERSISTENT
                st.rerun()
# Rerun to show the rest of the app

    # Only show the rest of the app if Gmail is authenticated
    if st.session_state.gmail_service:
        st.success("Gmail API is authenticated!")
        st.markdown("---")
        st.subheader("1. Upload Recipient List")
        st.info("Upload an Excel file with a column named `Email` (case-insensitive).")

        # --- File Uploader ---
        uploaded_file = st.file_uploader("Choose an Excel file", type=["xlsx", "xls"], key="excel_uploader")
        if uploaded_file is not None:
            # Streamlit gives you a file-like object directly, no need to save to temp file on disk if read_recipients_from_excel can handle it.
            # However, if read_recipients_from_excel strictly needs a path, you'd save it:
            try:
                # Assuming read_recipients_from_excel can take a file-like object or path
                # If it only takes a path, you need to save it to a temp file:
                temp_dir = "temp_uploads"
                os.makedirs(temp_dir, exist_ok=True)
                file_path = os.path.join(temp_dir, uploaded_file.name)
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())

                st.write(f"Reading recipients from: {uploaded_file.name}")
                recipients = read_recipients_from_excel(file_path) # Pass the path

                if not recipients:
                    st.warning("No valid emails found in the Excel file. Make sure there's an 'Email' column.")
                    st.session_state.recipients_list = []
                else:
                    st.session_state.recipients_list = recipients
                    st.success(f"Found {len(recipients)} recipient(s).")
                    st.expander("Show first 5 recipients").write([r.get('email', 'N/A') for r in recipients[:5]])
                    if len(recipients) > 5:
                        st.write(f"... and {len(recipients) - 5} more.")

            except Exception as e:
                st.error(f"Error reading Excel file: {e}")
                st.warning("Please ensure the Excel file has a column named 'Email' (case-insensitive) and is a valid .xlsx or .xls file.")
            finally:
                # Clean up the temporary file
                if 'file_path' in locals() and os.path.exists(file_path):
                    os.remove(file_path)
                    os.rmdir(temp_dir) # Only if temp_dir is empty

        st.markdown("---")
        st.subheader("2. Compose Your Email Message")
        current_message_input = st.text_area(
            "Your Email Message (Subject will be 'Important Message')",
            value=st.session_state.current_email_message,
            height=200,
            key="email_message_input"
        )
        if current_message_input:
            st.session_state.current_email_message = current_message_input
            # st.info("Message saved. Click 'Send Emails' when ready.") # Avoid re-displaying on every character input

        st.markdown("---")
        st.subheader("3. Send Emails")

        if st.button("Send Emails Now"):
            if not st.session_state.gmail_service:
                st.error("Gmail not authenticated. Please click 'Authenticate Gmail API' first.")
                return
            if not st.session_state.recipients_list:
                st.warning("No recipients found. Please upload an Excel file first.")
                return
            if not st.session_state.current_email_message:
                st.warning("No message provided. Please type your message in the text area.")
                return

            st.info(f"Sending message to {len(st.session_state.recipients_list)} recipients...")
            sent_count = 0
            failed_recipients = []
            progress_bar = st.progress(0)
            status_text = st.empty()

            for i, recipient_data in enumerate(st.session_state.recipients_list):
                recipient_email = recipient_data.get('email')
                if not recipient_email:
                    failed_recipients.append(str(recipient_data) + " (missing email field)")
                    status_text.warning(f"Skipping invalid recipient data: {recipient_data}")
                    progress_bar.progress((i + 1) / len(st.session_state.recipients_list))
                    continue

                try:
                    status_text.text(f"Attempting to send to: {recipient_email}...")
                    sent_status = send_gmail_message(
                        st.session_state.gmail_service, 'me', recipient_email, "Important Message", st.session_state.current_email_message
                    )
                    if sent_status:
                        sent_count += 1
                        status_text.success(f"✅ Sent to: `{recipient_email}`")
                    else:
                        failed_recipients.append(recipient_email)
                        status_text.error(f"❌ Failed to send to: `{recipient_email}` (unknown reason)")
                except Exception as e:
                    failed_recipients.append(recipient_email)
                    status_text.error(f"❌ Error sending to `{recipient_email}`: {e}")

                progress_bar.progress((i + 1) / len(st.session_state.recipients_list))
                import time
                time.sleep(0.1) # Small delay to make progress visible and avoid hitting API rate limits too fast (if applicable)

            st.markdown("---")
            final_report = f"**Email Sending Complete!**\n\n**Sent:** {sent_count}\n"
            if failed_recipients:
                final_report += "**Failed Recipients:**\n" + "\n".join(f"- `{fail}`" for fail in failed_recipients)
            st.markdown(final_report)

            # Reset state after sending
            st.session_state.current_email_message = ""
            st.session_state.recipients_list = []
            st.session_state.email_context = EmailContext() # Reset email context as well
            # st.experimental_rerun() # Rerun to clear inputs and reset the app for next use
                                    # Removed rerun as it can sometimes clear success messages too fast.
                                    # Users can manually refresh or interact again.

if __name__ == "__main__":
    main()

