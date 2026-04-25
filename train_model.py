import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

phishing_emails = [
    "URGENT: Your account has been suspended. Click here to verify your password immediately or lose access.",
    "Dear customer, your bank account requires immediate verification. Enter your credentials now.",
    "Congratulations! You have won $1,000,000. Click here to claim your prize immediately.",
    "Security alert: Unusual login detected. Verify your account password now to prevent suspension.",
    "Your PayPal account is limited. Please verify your identity by clicking the link below urgently.",
    "ACTION REQUIRED: Your Netflix subscription has expired. Update your payment info or account suspended.",
    "Dear user, click here to confirm your email address or your account will be deleted within 24 hours.",
    "IMMEDIATE ACTION REQUIRED: Your bank account has been compromised. Reset password now.",
    "You have 1 unread security message. Login now at http://secure-bank-login.xyz to read it.",
    "Warning: Your account access will expire. Verify credentials at http://192.168.1.paypal.com",
    "Final notice: verify your social security number and bank details to receive your tax refund.",
    "Your Apple ID has been locked due to suspicious activity. Click here to unlock immediately.",
    "Urgent: Credit card transaction declined. Update your billing info now to avoid account suspension.",
    "Dear valued customer, we detected suspicious activity. Please provide your password for verification.",
    "ALERT: Your email account will be closed unless you click this link and verify your details now.",
    "You are a winner! Claim your free iPhone by entering your credit card for shipping fee.",
    "Your password will expire in 24 hours. Click here to reset it now or lose all your data.",
    "Security breach detected on your account. Provide username and password to secure your account.",
    "Limited time offer: Verify your account details to receive $500 Amazon gift card today only.",
    "NOTICE: Your package delivery failed. Click here and enter your bank details to reschedule.",
    "Your account shows suspicious login from Russia. Verify your identity now to prevent lockout.",
    "Paypal: Account suspended for violating terms. Click to verify your identity and restore access.",
    "IRS NOTICE: You owe back taxes. Provide bank account details to avoid criminal prosecution.",
    "Win a MacBook Pro! Just verify your email and enter credit card details for a small processing fee.",
    "LAST WARNING: Failure to verify your account by clicking this link will result in permanent suspension.",
    "Dear account holder, unusual activity detected. Confirm your password and SSN to secure account.",
    "Congratulations, your account was selected for upgrade. Verify your bank details to proceed.",
    "Your Microsoft subscription expired. Enter your credit card number immediately to continue.",
    "Important security update required. Click here and enter your password to apply the security patch.",
    "Your email storage is full. Verify account by entering login credentials to continue using service.",
    "We detected unauthorized access. Send your password and OTP to our security team immediately.",
    "Your funds are on hold. Confirm your identity by providing bank account number and PIN.",
    "Exclusive offer! Wire transfer $100 to claim your $10,000 lottery winnings. Act now!",
    "CRITICAL: Your computer is infected. Call our toll-free number and provide remote access now.",
    "Your account was used in suspicious transactions. Verify identity at http://banklogin-secure.xyz",
]

safe_emails = [
    "Hi Sarah, just wanted to confirm our meeting tomorrow at 2pm. Let me know if you need to reschedule.",
    "Please find attached the quarterly report for your review. The figures look promising this quarter.",
    "Thanks for your order! Your package has been shipped and will arrive in 3-5 business days.",
    "Good morning team, a reminder that the company picnic is scheduled for this Saturday at the park.",
    "Your monthly bank statement is now available. Log in to your account to view your transactions.",
    "Hi, I wanted to follow up on our conversation last week about the project timeline.",
    "The weekly newsletter is here! Check out the latest company updates and upcoming events.",
    "Reminder: Annual performance reviews start next Monday. Please prepare your self-assessment.",
    "Your subscription to Premium has been renewed successfully. Thank you for your continued support.",
    "Meeting notes from yesterday's standup are attached. Please review and add any corrections.",
    "Hi John, can you please send me the latest version of the presentation before the meeting?",
    "Your flight booking confirmation for July 15th. Check-in opens 24 hours before departure.",
    "Great news! Your job application has been received and we'll be in touch within two weeks.",
    "The team lunch is confirmed for Friday at 12:30pm. We'll be going to the new Italian place downtown.",
    "Attached is the invoice for services rendered in May. Payment terms are net 30 days.",
    "Just a heads up that I'll be out of office next week for vacation. Contact my manager for urgent matters.",
    "Your library book is due in 5 days. You can renew it online through your account.",
    "Happy Birthday! Wishing you a wonderful day filled with joy and celebration.",
    "Thank you for attending our webinar. Here is the recording and slide deck as promised.",
    "The project has been completed successfully. Please find the final report attached.",
    "Reminder: Your dentist appointment is confirmed for Thursday at 10am at our downtown clinic.",
    "We're pleased to inform you that your loan application has been approved. Contact us to proceed.",
    "The board meeting minutes from last Tuesday are now available on the intranet.",
    "Your online order has been delivered to your front door. Enjoy your purchase!",
    "Hi, following up on the proposal I sent last week. Would love to chat when you have time.",
    "The software update has been deployed successfully to all production servers.",
    "Please complete the annual compliance training by end of month. Link below to get started.",
    "Your gym membership renewal is coming up. We hope you've enjoyed your fitness journey with us.",
    "Team outing is planned for next Friday evening. More details to follow from HR.",
    "Your tax documents for 2024 are ready. Please log in to your account at the official IRS website.",
    "Hi team, the new office supplies have arrived. Please collect them from the reception desk.",
    "Your resume has been shortlisted. We would like to schedule a technical interview next week.",
    "The research paper you submitted has been accepted for publication. Congratulations!",
    "Friendly reminder: please submit your timesheet by Friday 5pm for payroll processing.",
    "We have updated our privacy policy. You can review the changes on our official website.",
]

X = phishing_emails + safe_emails
y = [1] * len(phishing_emails) + [0] * len(safe_emails)

pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=5000, stop_words='english', sublinear_tf=True)),
    ('clf', LogisticRegression(max_iter=1000, C=1.0, random_state=42))
])
pipeline.fit(X, y)

with open('model.pkl', 'wb') as f:
    pickle.dump(pipeline, f)

print(f"Model trained! {len(phishing_emails)} phishing + {len(safe_emails)} safe = {len(X)} total samples")
