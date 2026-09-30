"""Realistic fixture emails. Numbers, names and accounts are fictitious."""

from __future__ import annotations

import datetime as dt

from mailwarden.core.models import FetchedMessage

WHEN = dt.datetime(2026, 9, 30, 9, 0, tzinfo=dt.UTC)


def make(sender: str, name: str, subject: str, body: str, **kw) -> FetchedMessage:
    return FetchedMessage(
        user_id="local",
        account="personal",
        message_id=kw.pop("message_id", "m1"),
        sender_address=sender,
        sender_name=name,
        subject=subject,
        body_text=body,
        received_at=WHEN,
        **kw,
    )


# (id, sender, display name, subject, body)
SENSITIVE = [
    ("hdfc_debit", "alerts@hdfcbank.net", "HDFC Bank InstaAlerts", "Alert : Update on your HDFC Bank A/c",
     "Dear Customer, Rs.2,450.00 has been debited from account **4821 to VPA swiggy@ybl on 30-09-26. "
     "Your UPI transaction reference number is 426391837261. If you did not authorize this, call 18002586161."),
    ("icici_cc", "credit_cards@icicibank.com", "ICICI Bank", "Transaction alert for your ICICI Bank Credit Card",
     "INR 1,299.00 spent on ICICI Bank Card XX9012 on 30-Sep-26 at AMAZON. Avl Limit: INR 84,211.50."),
    ("sbi_otp", "donotreply@sbi.co.in", "State Bank of India", "OTP for online transaction",
     "Your OTP for transaction of Rs 5000 is 739201. Do not share it with anyone. SBI never asks for OTP."),
    ("axis_login", "alerts@axisbank.com", "Axis Bank", "Login to Internet Banking",
     "You have successfully logged in to Axis Bank Internet Banking on 30/09/2026 at 09:12 from a new device."),
    ("kotak_statement", "statements@kotak.com", "Kotak Mahindra Bank", "Your account statement for September 2026",
     "Please find attached your e-statement. The password is your first 4 letters of name and DOB in DDMM."),
    ("phonepe", "noreply@phonepe.com", "PhonePe", "Payment successful",
     "Paid ₹350 to Ramesh Kirana. UPI Ref No 426912345678. Debited from HDFC Bank XX4821."),
    ("paytm_kyc", "no-reply@paytm.com", "Paytm", "Complete your KYC to continue using Paytm Wallet",
     "Your wallet will be restricted. Complete Min-KYC with your PAN card and Aadhaar within 7 days."),
    ("gpay", "googlepay-noreply@google.com", "Google Pay", "You received ₹1,200",
     "Priya sent you ₹1,200. The money has been credited to your bank account ending in 4821."),
    ("google_security", "no-reply@accounts.google.com", "Google", "Security alert",
     "A new sign-in on Mac. We noticed a new sign-in to your Google Account on a Mac device. If this was you, you don't need to do anything."),
    ("microsoft_signin", "account-security-noreply@accountprotection.microsoft.com", "Microsoft account team",
     "Microsoft account unusual sign-in activity", "We detected something unusual about a recent sign-in to the Microsoft account."),
    ("apple_code", "appleid@id.apple.com", "Apple", "Your Apple Account code",
     "Your Apple Account verification code is: 482913. Don't share it with anyone."),
    ("amazon_otp", "account-update@amazon.in", "Amazon.in", "Amazon password assistance",
     "To authenticate, please use the following One Time Password (OTP): 614022. Don't share this OTP with anyone."),
    ("zerodha_otp", "noreply@zerodha.net", "Zerodha", "Kite login OTP",
     "Your OTP to login to Kite is 552190. It is valid for 5 minutes."),
    ("groww", "noreply@groww.in", "Groww", "Your SIP instalment was successful",
     "₹5,000 has been debited via autopay mandate for your mutual fund SIP."),
    ("cdsl", "easi@cdslindia.com", "CDSL", "Transaction alert from CDSL",
     "Debit transaction in your demat account for 10 shares."),
    ("income_tax", "donotreply@incometax.gov.in", "Income Tax Department", "ITR-V acknowledgement for AY 2026-27",
     "Your Income Tax Return for Assessment Year 2026-27 has been filed. PAN: ABCDE1234F."),
    ("uidai", "noreply@uidai.gov.in", "UIDAI", "Aadhaar authentication history",
     "Your Aadhaar was used for authentication on 30-09-2026."),
    ("pan_protean", "service@protean-tinpan.com", "Protean", "PAN application status",
     "Your application for new PAN has been processed. Acknowledgement No 881234567890123."),
    ("cred", "hello@cred.club", "CRED", "bill payment successful",
     "Payment of ₹12,400 towards your credit card ending 9012 is successful."),
    # Content-only catches: unknown senders not in any tier.
    ("unknown_otp", "noreply@some-mailer.com", "Some Service", "Your verification code",
     "Use 902113 to verify your email address. This code expires in 10 minutes."),
    ("unknown_code_no_keyword", "noreply@app.example.org", "Example App", "Sign in to Example",
     "Enter this code on the sign in page: 3391"),
    ("password_reset", "noreply@github.com", "GitHub", "[GitHub] Please reset your password",
     "We heard that you lost your GitHub password. Sorry about that! Use the link below to reset your password."),
    ("two_factor", "no-reply@notion.so", "Notion", "Two-factor authentication enabled",
     "Two-factor authentication is now enabled on your account."),
    ("new_device_generic", "security@discordapp.com", "Discord", "Verify login from new location",
     "Someone tried to log into your account from a new location."),
    ("delivery_otp", "shipment-tracking@amazon.in", "Amazon.in", "Your package is out for delivery",
     "Share OTP 4471 with the delivery agent to receive your package."),
    ("hindi_otp", "alerts@some-bank-mailer.com", "Alerts", "सूचना",
     "आपका ओटीपी 839201 है। इसे किसी के साथ साझा न करें।"),
    ("new_domain_bank_in", "alerts@hdfc.bank.in", "Alerts", "Statement ready",
     "Your monthly statement is ready."),
    # Obfuscation attempts.
    ("obfuscated_otp", "noreply@shop.example.com", "Shop", "Your O.T.P",
     "Your O-T-P is ４８２９１３ (please do not share)."),
    ("zero_width_otp", "noreply@shop.example.com", "Shop", "Log in",
     "Your o​t​p is 4​8​2​9​1​3"),
    ("cyrillic_otp", "noreply@shop.example.com", "Shop", "ОТР inside",
     "Your ОТР is 552011."),
    ("split_code", "noreply@shop.example.com", "Shop", "Almost there",
     "Your verification code: 482 913"),
    # A PRIORITY sender with sensitive content is still sensitive.
    ("priority_sender_code", "support@hackerrank.com", "HackerRank", "HackerRank verification code",
     "Your verification code is 771203. Enter it to log in to HackerRank."),
    ("interview_with_passcode", "no-reply@greenhouse.io", "Acme Recruiting", "Interview confirmation",
     "Your interview is on Oct 3. Zoom: meeting ID 812 3456 7890, passcode 339122."),
    # Name heuristic: bank-branded display name from an unlisted domain.
    ("bank_display_name", "info@mailer-xyz.com", "Yes Bank", "An update for you",
     "We have an update regarding your relationship with us."),
]

SAFE = [
    ("greenhouse_received", "no-reply@us.greenhouse-mail.io", "Acme Careers", "Thank you for applying to Acme",
     "Hi Harshil, thanks for applying for the Software Engineer role at Acme. Our team will review your application and get back to you."),
    ("hackerrank_invite", "support@hackerrankforwork.com", "Globex Hiring Team", "Globex: Online assessment invitation",
     "You have been invited to take the Globex online test. Please complete it within 7 days. Duration: 90 minutes. Start here: https://www.hackerrank.com/test/abc/login"),
    ("lever_interview", "no-reply@hire.lever.co", "Initech", "Next steps: interview with Initech",
     "We'd love to schedule a 45 minute technical interview next week. Please pick a slot using the link: https://calendly.com/initech/tech"),
    ("rejection", "careers@umbrella.com", "Umbrella Corp", "Your application to Umbrella",
     "Thank you for your interest. After careful consideration, we have decided to move forward with other candidates."),
    ("newsletter", "hello@newsletter.bytebytego.com", "ByteByteGo", "System design: rate limiters",
     "This week we look at token bucket and leaky bucket algorithms, with diagrams."),
    ("friend", "rahul.k@gmail.com", "Rahul", "Dinner on Friday?",
     "Hey! Are you free for dinner on Friday at 8? Thinking of that new place in Indiranagar."),
    ("github_pr", "notifications@github.com", "GitHub", "[org/repo] Fix flaky test (PR #1024)",
     "@alice approved these changes. Merged into main."),
    ("pan_india_job", "jobs@naukri.com", "Naukri", "Backend roles, PAN India",
     "15 new Backend Developer jobs matching your profile. Locations: PAN India, remote."),
]
