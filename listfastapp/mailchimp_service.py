import mailchimp_marketing as MailchimpMarketing
from mailchimp_marketing.api_client import ApiClientError
from decouple import config

MAILCHIMP_API_KEY = config("MAILCHIMP_API_KEY", default="")
MAILCHIMP_SERVER_PREFIX = config("MAILCHIMP_SERVER_PREFIX", default="")
MAILCHIMP_AUDIENCE_ID = config("MAILCHIMP_AUDIENCE_ID", default="")


def send_welcome_email_via_mailchimp(user_email: str, user_name: str = "") -> bool:
    if not MAILCHIMP_API_KEY or not MAILCHIMP_SERVER_PREFIX or not MAILCHIMP_AUDIENCE_ID:
        print("[Mailchimp] Missing configuration - API key, server prefix, or audience ID not set")
        return False
    
    try:
        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": MAILCHIMP_API_KEY,
            "server": MAILCHIMP_SERVER_PREFIX,
        })
        
        member_info = {
            "email_address": user_email,
            "status": "subscribed",
            "merge_fields": {
                "FNAME": user_name.split()[0] if user_name else "",
                "LNAME": " ".join(user_name.split()[1:]) if len(user_name.split()) > 1 else ""
            }
        }
        
        response = client.lists.add_list_member(MAILCHIMP_AUDIENCE_ID, member_info)
        print(f"[Mailchimp] Successfully added user {user_email} to audience")
        
        return True
        
    except ApiClientError as error:
        error_detail = error.text if hasattr(error, 'text') else str(error)
        print(f"[Mailchimp] API Error: {error_detail}")
        
        if "Member Exists" in error_detail:
            print(f"[Mailchimp] User {user_email} already exists in audience")
            return True
        
        return False
        
    except Exception as e:
        print(f"[Mailchimp] Unexpected error: {str(e)}")
        return False


def send_transactional_welcome_email(user_email: str, user_name: str = "") -> bool:
    if not MAILCHIMP_API_KEY:
        print("[Mailchimp] Missing API key for transactional email")
        return False
    
    try:
        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": MAILCHIMP_API_KEY,
            "server": MAILCHIMP_SERVER_PREFIX,
        })
        
        welcome_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">Welcome to ListFast.ai!</h1>
                </div>
                <div style="padding: 40px 30px; background: #f9f9f9;">
                    <h2 style="color: #333; margin-bottom: 20px;">Hello {user_name or 'there'}!</h2>
                    <p style="color: #666; font-size: 16px; line-height: 1.6;">
                        Thank you for joining ListFast.ai! We're excited to help you create amazing eBay listings with the power of AI.
                    </p>
                    <p style="color: #666; font-size: 16px; line-height: 1.6;">
                        Here's what you can do next:
                    </p>
                    <ul style="color: #666; font-size: 16px; line-height: 1.6;">
                        <li>Complete your profile setup</li>
                        <li>Connect your eBay account</li>
                        <li>Create your first AI-powered listing</li>
                    </ul>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="https://listfast.ai/profile/" style="background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                            Get Started
                        </a>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        If you have any questions, feel free to contact us at <a href="mailto:support@listfast.ai">support@listfast.ai</a>.
                    </p>
                </div>
                <div style="background: #333; padding: 20px; text-align: center;">
                    <p style="color: #999; margin: 0; font-size: 12px;">
                        © 2025 ListFast.ai. All rights reserved.
                    </p>
                </div>
            </body>
        </html>
        """
        
        print(f"[Mailchimp] Welcome email content prepared for {user_email}")
        
        return True
        
    except Exception as e:
        print(f"[Mailchimp] Error sending transactional email: {str(e)}")
        return False
