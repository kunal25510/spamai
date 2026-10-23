import re

def analyze_general_message(text):
    """
    Analyzes generic messages from SMS, WhatsApp, Telegram, Email, etc.
    Flags common scam categories: KYC/banking, OTP theft, lottery, parcel fees, UPI scams.
    """
    clean_text = text.lower()
    reasons = []
    score = 0

    # 1. Bank KYC / Account Suspension / Electricity Disconnection
    kyc_patterns = [
        r"\bkyc\b", r"pan card", r"aadhaar", r"account (?:suspended|blocked|deactivated|frozen|hold)",
        r"electricity.*disconnect", r"update your (?:bank|kyc|pan)",
        r"bank account (?:blocked|hold)", r"verify your account details",
        r"bill unpaid.*disconnect"
    ]
    if any(re.search(pat, clean_text) for pat in kyc_patterns):
        score += 35
        reasons.append("Bank KYC or account suspension/disconnection threat detected.")

    # 2. OTP / Password / PIN / Credential Requests
    otp_patterns = [
        r"\botp\b", r"one[- ]time password", r"verification code", r"share (?:your )?(?:code|pin|otp)",
        r"send (?:me )?(?:the )?(?:otp|code)", r"upi pin", r"atm pin", r"cvv",
        r"enter (?:your )?password", r"provide (?:your )?login"
    ]
    if any(re.search(pat, clean_text) for pat in otp_patterns):
        score += 45
        reasons.append("Requests sensitive credentials, OTP, or PIN directly from the recipient.")

    # 3. Lottery / Prize / Reward Scams
    lottery_patterns = [
        r"you (?:have )?won", r"lottery", r"lucky (?:draw|winner)", r"cash prize",
        r"claim (?:your )?(?:reward|prize|money)", r"congratulations.*winner",
        r"free (?:gift|iphone|cash|money)", r"crore.*winner"
    ]
    if any(re.search(pat, clean_text) for pat in lottery_patterns):
        score += 40
        reasons.append("Lottery, giveaway, or unearned cash prize lure detected.")

    # 4. Parcel / Courier / Delivery Fee Scams
    parcel_patterns = [
        r"parcel", r"package (?:held|stuck|pending)", r"delivery (?:fee|charge|failed|attempt)",
        r"customs (?:duty|clearance|fee)", r"india post.*delivery", r"courier.*fee",
        r"pay (?:small )?(?:fee|amount) to (?:release|receive)"
    ]
    if any(re.search(pat, clean_text) for pat in parcel_patterns):
        score += 35
        reasons.append("Fake parcel delivery or customs fee payment trap detected.")

    # 5. UPI / QR Code / Payment Reversal Scams
    upi_patterns = [
        r"scan (?:this )?qr (?:code )?to receive", r"receive (?:money|refund) by (?:entering|typing) upi",
        r"send money to (?:this )?upi", r"overpaid you.*refund", r"urgent money transfer"
    ]
    if any(re.search(pat, clean_text) for pat in upi_patterns):
        score += 40
        reasons.append("Misleading payment scheme (e.g., QR code scan or UPI PIN request to receive funds).")

    # 6. Urgent or Threatening Language
    urgent_patterns = [
        r"immediately", r"act now", r"urgent", r"within 24 hours", r"last warning",
        r"final notice", r"will be permanently deleted", r"take immediate action",
        r"\btonight\b", r"\btoday\b", r"\bnow\b"
    ]
    if any(re.search(pat, clean_text) for pat in urgent_patterns):
        score += 15
        reasons.append("High-pressure urgency or artificial deadline tactics employed.")

    # 7. Suspicious Links or Redirection
    link_patterns = [
        r"https?://", r"bit\.ly", r"tinyurl\.com", r"t\.co", r"cutt\.ly", r"wa\.me",
        r"click (?:here|the link|below)", r"open link"
    ]
    if any(re.search(pat, clean_text) for pat in link_patterns):
        score += 15
        reasons.append("Contains an embedded link or request to click external URL.")

    # Score clamping and level
    score = min(score, 100)
    if score >= 50:
        level = "HIGH"
        msg = "High risk: Message exhibits strong characteristics of known financial, credential, or impersonation scams."
    elif score >= 25:
        level = "MEDIUM"
        msg = "Medium risk: Message contains caution indicators such as urgency or unfamiliar payment links."
    else:
        level = "LOW"
        msg = "Low risk: No common scam triggers, credential theft requests, or financial traps detected."
        if not reasons:
            reasons.append("No typical scam triggers (OTP requests, urgent threats, or fake prize lures) identified.")

    return {
        "risk_level": level,
        "risk_score": score,
        "reasons": reasons,
        "message": msg,
        "analysis_type": "message",
        "details": {
            "indicators_found": len(reasons),
            "disclaimer": "Heuristic evaluation of message text. Always verify unexpected requests through trusted channels."
        }
    }


def analyze_job_offer(text):
    """
    Specialized analyzer for recruitment and internship messages.
    Distinguishes legitimate offers/courses from fraudulent upfront fee demands and guaranteed job schemes.
    """
    clean_text = text.lower()
    reasons = []
    score = 0

    # 1. Upfront Payment / Registration / Training Fees (Primary Red Flag)
    fee_patterns = [
        r"registration fee", r"training (?:fee|cost|charge)", r"security deposit",
        r"pay (?:rs\.?|inr|\$|\d+).*(?:interview|offer|joining|internship)",
        r"document verification (?:fee|charge)", r"laptop deposit", r"processing (?:fee|charge)",
        r"exam fee for placement", r"buy (?:training|course) to get (?:job|internship)"
    ]
    fee_detected = any(re.search(pat, clean_text) for pat in fee_patterns)
    if fee_detected:
        score += 45
        reasons.append("Demands upfront payment for registration, training, documentation, or placement.")

    # 2. Unrealistic Guaranteed Placement / Exaggerated Compensation
    unrealistic_patterns = [
        r"100% (?:guaranteed|placement|job)", r"guaranteed (?:placement|job|hiring)",
        r"earn \d{4,6} (?:daily|per day|hourly)", r"work 1 hour earn",
        r"no (?:interview|test|experience) (?:needed|required) direct (?:selection|joining)",
        r"daily payout.*earn from home", r"part[- ]time job earn \d{4,6}"
    ]
    if any(re.search(pat, clean_text) for pat in unrealistic_patterns):
        score += 35
        reasons.append("Unrealistic guarantees (e.g. 100% job guarantee without interview or exaggerated daily earnings).")

    # 3. Informal Communication Channels for Enterprise Hiring
    informal_channels = [
        r"telegram", r"whatsapp (?:only|me|now)", r"message (?:on|at) @\w+",
        r"contact hr (?:on|via) (?:telegram|whatsapp)", r"chat with hr on telegram"
    ]
    if any(re.search(pat, clean_text) for pat in informal_channels):
        score += 25
        reasons.append("Directs candidates to informal chat apps (Telegram/WhatsApp) for official enterprise hiring.")

    # 4. Sensitive Credentials / Banking Demands Prior to Interview
    cred_patterns = [
        r"\botp\b", r"bank (?:account|details|password)", r"credit card", r"upi pin",
        r"send (?:your )?(?:id proof|aadhaar|pan) (?:immediately|first)"
    ]
    if any(re.search(pat, clean_text) for pat in cred_patterns):
        score += 35
        reasons.append("Demands banking details, OTP, or sensitive financial information prematurely.")

    # 5. Free Webmail Domain for Major Corporations
    major_corps = ["google", "microsoft", "amazon", "apple", "meta", "netflix", "infosys", "tcs", "wipro"]
    free_mail = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com"]
    for corp in major_corps:
        if corp in clean_text:
            if any(mail in clean_text for mail in free_mail):
                score += 35
                reasons.append(f"Claims affiliation with {corp.capitalize()} but uses a free public email provider.")
                break

    # 6. Pressure / Scarcity Tactics
    pressure_patterns = [
        r"only \d+ (?:slots?|seats?) left", r"offer expires (?:in \d+ hours|today)",
        r"last chance to apply", r"immediate joining today only"
    ]
    if any(re.search(pat, clean_text) for pat in pressure_patterns):
        score += 15
        reasons.append("Uses artificial scarcity or pressure tactics to rush your decision.")

    # Nuanced balance: check if it's purely an informative training/course without deceptive guarantees
    is_benign_training = ("training" in clean_text or "course" in clean_text or "bootcamp" in clean_text) and not fee_detected and score < 25

    score = min(score, 100)
    if score >= 50:
        level = "HIGH"
        msg = "High risk: Recruitment message exhibits key red flags of employment or internship fraud."
    elif score >= 25:
        level = "MEDIUM"
        msg = "Medium risk: Caution advised due to informal communication channels or upfront fee mentions."
    else:
        level = "LOW"
        msg = "Low risk: Message appears to be a standard job outreach or career opportunity without predatory indicators."
        if not reasons:
            reasons.append("No upfront payment requests, unrealistic salary promises, or informal recruiter tactics detected.")

    return {
        "risk_level": level,
        "risk_score": score,
        "reasons": reasons,
        "message": msg,
        "analysis_type": "job",
        "details": {
            "indicators_found": len(reasons),
            "disclaimer": "Recruitment verification check. Genuine companies never charge candidates for job offers or interviews."
        }
    }


def analyze_github_linkedin(text):
    """
    Specialized analyzer for developer and professional outreach on GitHub & LinkedIn.
    Flags malicious code execution, credential/token theft, and fake assessment downloads.
    Avoids false positives for normal networking messages.
    """
    clean_text = text.lower()
    reasons = []
    score = 0

    # 1. Dangerous Shell Commands & Remote Script Execution
    exec_patterns = [
        r"curl\s+[^\n|]+\|\s*(?:ba)?sh", r"wget\s+[^\n|]+\|\s*(?:ba)?sh",
        r"powershell\s+-(?:enc|encodedcommand)", r"invoke-webrequest", r"iex\s*\(",
        r"run this (?:command|script|binary)", r"npm\s+i(?:nstall)?\s+-g\s+http",
        r"pip\s+install\s+http", r"chmod\s+\+x"
    ]
    if any(re.search(pat, clean_text) for pat in exec_patterns):
        score += 60
        reasons.append("Instructs execution of untrusted remote scripts or shell commands (e.g. curl | bash, PowerShell).")

    # 2. Suspicious File Download / Executable Lures
    file_lures = [
        r"\.exe\b", r"\.scr\b", r"\.bat\b", r"\.cmd\b", r"\.vbs\b",
        r"download (?:this )?(?:zip|file|binary) to (?:run|test|build)",
        r"execute (?:the )?(?:setup|installer)", r"disable (?:your )?antivirus"
    ]
    if any(re.search(pat, clean_text) for pat in file_lures):
        score += 45
        reasons.append("Prompts downloading and executing binary files or disabling antivirus protection.")

    # 3. Credential, Token, or Secret Key Harvesting
    token_patterns = [
        r"personal access token", r"\bpat\b", r"ssh key", r"api key", r"secret key",
        r"github (?:password|token|credentials)", r"linkedin (?:password|login)",
        r"send (?:your )?private key", r"authorize this app"
    ]
    if any(re.search(pat, clean_text) for pat in token_patterns):
        score += 50
        reasons.append("Requests developer secrets, Personal Access Tokens (PAT), SSH keys, or platform passwords.")

    # 4. Fake Collaboration & Crypto / Web3 Project Lures
    collab_lures = [
        r"crypto (?:project|token|airdrop)", r"web3 (?:project|audit)",
        r"test our game (?:build|demo)", r"clone and run this private repo",
        r"paid assessment.*download zip"
    ]
    if any(re.search(pat, clean_text) for pat in collab_lures):
        score += 30
        reasons.append("Presents unsolicited repository collaboration or game/crypto testing lures commonly tied to infostealers.")

    # 5. Redirection to Telegram/Discord for Code / Interviews
    redirect_patterns = [
        r"telegram", r"discord\.gg", r"contact (?:me )?on telegram", r"dm on discord"
    ]
    if any(re.search(pat, clean_text) for pat in redirect_patterns):
        score += 15
        reasons.append("Redirects professional technical discussions to informal channels (Telegram/Discord).")

    # Score Clamping
    score = min(score, 100)
    if score >= 50:
        level = "HIGH"
        msg = "High risk: Message exhibits tactics typical of developer-targeted malware, infostealers, or token theft."
    elif score >= 25:
        level = "MEDIUM"
        msg = "Medium risk: Caution advised when handling unsolicited collaboration invites, external zips, or scripts."
    else:
        level = "LOW"
        msg = "Low risk: Appears to be a standard professional networking or collaboration inquiry."
        if not reasons:
            reasons.append("No malicious command execution, token harvesting, or suspicious binary lures detected.")

    return {
        "risk_level": level,
        "risk_score": score,
        "reasons": reasons,
        "message": msg,
        "analysis_type": "github_linkedin",
        "details": {
            "indicators_found": len(reasons),
            "disclaimer": "Never execute arbitrary scripts, disable security controls, or share private tokens/SSH keys."
        }
    }
