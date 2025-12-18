#!/usr/bin/env python3
import sys
import argparse
import datetime

# Sentinel Phish - Part of Cyber Sentinel Human Dominion
# Generates phishing scenario templates. FOR EDUCATIONAL PURPOSES ONLY.

def banner():
    print("=" * 60)
    print("      🎭 SENTINEL PHISH: SOCIAL ENGINEERING TOOLKIT 🎭")
    print("=" * 60)

def generate_template(scenario, target_name, company_name):
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    
    print(f"[*] Generating '{scenario}' template for {target_name} at {company_name}")
    print("-" * 60)
    
    if scenario == "ceo_urgent":
        subject = f"URGENT: Request provided - {date_str}"
        body = f"""
Hello {target_name},

I am currently in a meeting and cannot take calls. I need you to process a wire transfer immediately for a new vendor to secure our supply chain.

Please reply with the current operational liquidity report so I can forward the details. Do not discuss this with anyone yet as the deal is strictly confidential.

Regards,
CEO of {company_name}
Sent from my iPhone
        """
    elif scenario == "it_password":
        subject = f"ACTION REQUIRED: Security Audit - Password Expiry"
        body = f"""
Dear {target_name},

This is an automated notification from the {company_name} IT Support Desk.

Your directory account password is set to expire in 24 hours. To retain access to your email and files, please validate your credentials immediately at the portal below:

[ LINK TO FAKE LOGIN PAGE ]

Failure to update will result in account lockout.

Regards,
IT Admin Team
        """
    elif scenario == "hr_bonus":
        subject = f"Confidential: Year-End Performance Bonus Allocation"
        body = f"""
Hi {target_name},

We are pleased to inform you that you are eligible for the Q4 Performance Bonus.

Attached is the breakdown of your allocation. Please review the document and sign the acknowledgment form by EOD.

[ MALICIOUS_EXCEL_FILE.xlsm ]

Best,
Human Resources
{company_name}
        """
    else:
        print("[!] Unknown scenario.")
        return

    print(f"Subject: {subject}")
    print(f"Body:\n{body}")
    print("-" * 60)

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="Sentinel Phish Template Generator")
    parser.add_argument("--scenario", help="Scenario type (ceo_urgent, it_password, hr_bonus)", required=True)
    parser.add_argument("--target", help="Target Name", default="Employee")
    parser.add_argument("--company", help="Target Company", default="Corp Inc.")
    
    args = parser.parse_args()
    
    generate_template(args.scenario, args.target, args.company)
