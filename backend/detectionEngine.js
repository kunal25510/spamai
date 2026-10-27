/**
 * Sentinel AI Security Agent — Centralized Layered Detection Engine
 * 
 * Provides evidence-based, explainable detection of phishing, scams, impersonation,
 * credential theft, payment fraud, fake alerts, OTP scams, and social-engineering attacks.
 * 
 * Single, consistent scoring interpretation:
 * RISK SCORE: 0 to 100 (where HIGHER means MORE DANGEROUS)
 * - 0–19:   Likely safe
 * - 20–39:  Needs caution
 * - 40–69:  Suspicious
 * - 70–100: High risk
 */

const crypto = require("crypto");
const dns = require("dns");

// =========================================================================
// 1. PUBLIC SUFFIX & MULTI-PART TLD PARSER
// =========================================================================

const COMMON_TWO_PART_TLDS = new Set([
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in",
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "net.br", "org.br",
    "co.za", "org.za", "gov.za",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.sg", "edu.sg", "gov.sg",
    "com.my", "edu.my", "gov.my"
]);

const HIGH_RISK_TLDS = new Set([
    "xyz", "top", "click", "buzz", "fit", "work", "rest", "tk", "ml", "ga", "cf", "gq",
    "icu", "monster", "bar", "cam", "loan", "win", "gdn", "stream", "racing", "kim"
]);

const KNOWN_SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "bit.do",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "v.gd", "clck.ru", "qr.ae"
]);

const TARGETED_BRANDS = {
    google: ["google.com", "googlemail.com", "googleapis.com", "google.co.in", "accounts.google.com"],
    microsoft: ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com"],
    apple: ["apple.com", "icloud.com"],
    amazon: ["amazon.com", "amazon.in", "amazonsellerservices.com", "amazon.co.uk"],
    paypal: ["paypal.com"],
    netflix: ["netflix.com"],
    sbi: ["sbi.co.in", "onlinesbi.sbi", "statebankofindia.com"],
    hdfc: ["hdfcbank.com", "hdfcbank.net"],
    icici: ["icicibank.com"],
    indiapost: ["indiapost.gov.in", "ippb.in", "ippbonline.com", "ippbonline.co.in"],
    facebook: ["facebook.com", "facebookmail.com", "fb.me"],
    linkedin: ["linkedin.com", "licdn.com"],
    github: ["github.com"],
    fedex: ["fedex.com"],
    dhl: ["dhl.com", "dhl.de"],
    whatsapp: ["whatsapp.com", "wa.me"],
    telegram: ["telegram.org", "t.me"],
    instagram: ["instagram.com"],
    binance: ["binance.com"],
    paytm: ["paytm.com"],
    unstop: ["unstop.com", "unstop.news"],
    canva: ["canva.com"],
    spotify: ["spotify.com"],
    railway: ["railway.app", "railway.com"],
    render: ["render.com"]
};

function isDisplayingDomainOrUrl(text) {
    if (!text || typeof text !== "string") return false;
    const clean = text.trim();
    if (/\s/.test(clean)) return false;
    if (/^(?:https?:\/\/|www\.)[a-zA-Z0-9-]/i.test(clean)) return true;
    const parts = clean.split("/")[0].split(":")[0].split(".");
    if (parts.length >= 2) {
        const tld = parts[parts.length - 1].toLowerCase();
        return /^[a-z]{2,12}$/i.test(tld) && parts.every(p => /^[a-z0-9-]+$/i.test(p));
    }
    return false;
}

function parseDomain(inputUrlOrHost) {
    if (!inputUrlOrHost) {
        return { host: "", rootDomain: "", sld: "", tld: "", isIp: false };
    }

    let host = String(inputUrlOrHost).trim().toLowerCase();
    if (host.includes("@")) {
        host = host.split("@").pop().trim();
    }
    try {
        if (host.includes("://")) {
            const parsed = new URL(host);
            host = parsed.hostname;
        } else {
            host = host.split("/")[0].split(":")[0];
        }
    } catch (_) {
        host = host.split("/")[0].split(":")[0];
    }

    host = host.replace(/^\.+|\.+$/g, "");

    // Check if IPv4
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    if (isIp) {
        return { host, rootDomain: host, sld: host, tld: "", isIp: true };
    }

    const parts = host.split(".");
    if (parts.length <= 1) {
        return { host, rootDomain: host, sld: host, tld: "", isIp: false };
    }

    const lastTwo = parts.slice(-2).join(".");
    let rootDomain = "";
    let sld = "";
    let tld = "";

    if (parts.length >= 3 && COMMON_TWO_PART_TLDS.has(lastTwo)) {
        rootDomain = parts.slice(-3).join(".");
        sld = parts[parts.length - 3];
        tld = lastTwo;
    } else {
        rootDomain = parts.slice(-2).join(".");
        sld = parts[parts.length - 2];
        tld = parts[parts.length - 1];
    }

    return { host, rootDomain, sld, tld, isIp: false };
}

function detectLookalikeDomain(rootDomain) {
    if (!rootDomain) return null;
    const { sld } = parseDomain(rootDomain);
    const cleanSld = sld.toLowerCase().replace(/[^a-z0-9]/g, "");

    // Common character substitutions (homoglyphs / visual typos)
    const normalized = cleanSld
        .replace(/0/g, "o")
        .replace(/1/g, "l")
        .replace(/5/g, "s")
        .replace(/vv/g, "w")
        .replace(/rn/g, "m");

    for (const [brand, validDomains] of Object.entries(TARGETED_BRANDS)) {
        // If it's already one of the authentic domains for the brand, it's not a lookalike
        if (validDomains.includes(rootDomain)) {
            continue;
        }

        if (normalized === brand || (normalized.length >= 4 && (normalized.startsWith(brand) || normalized.endsWith(brand)))) {
            // Check if it's an unauthorized variant imitating the brand
            return {
                targetBrand: brand,
                description: `Domain '${rootDomain}' deceptively imitates brand '${brand}'.`
            };
        }
    }
    return null;
}

// =========================================================================
// 2. LAYER B: URL & DOMAIN EVIDENCE EXTRACTOR
// =========================================================================

function extractUrlsFromText(text) {
    if (!text || typeof text !== "string") return [];
    const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+|(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|info|buzz|ru|cn|in|app|io|me|cc|link|tk|ga|cf|gq|ml|live|site|online)(?:\/[^\s<>"'{}|\\^`]*)?/gi;
    const matches = text.match(urlRegex) || [];
    return matches.map(u => {
        let clean = u.trim().replace(/[.,;:)\]]+$/, "");
        if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
            clean = "https://" + clean;
        }
        return clean;
    });
}

function analyzeUrls(urls, textContext = "") {
    const findings = [];
    const analyzedUrls = [];

    const urlList = Array.isArray(urls) ? [...urls] : [];
    if (textContext) {
        const fromText = extractUrlsFromText(textContext);
        for (const u of fromText) {
            if (!urlList.some(item => (typeof item === "string" ? item : item?.href) === u)) {
                urlList.push(u);
            }
        }
    }

    for (const urlItem of urlList) {
        const rawHref = typeof urlItem === "string" ? urlItem : urlItem?.href || "";
        const anchorText = typeof urlItem === "object" ? urlItem?.text || "" : "";
        if (!rawHref) continue;

        const parsed = parseDomain(rawHref);
        const urlFlags = [];
        let urlRisk = "safe";

        // Check 1: Raw IP URL
        if (parsed.isIp) {
            urlFlags.push("RAW_IP_DESTINATION");
            urlRisk = "suspicious";
            findings.push({
                id: "URL_RAW_IP",
                title: "Raw IP Address Destination",
                explanation: `Link destination uses a raw IP address (${parsed.host}) instead of a registered domain.`,
                evidence: rawHref,
                severity: "HIGH",
                source: "URL",
                confidence: 90,
                status: "confirmed"
            });
        }

        // Check 2: Lookalike / Typosquatted Domain
        const lookalike = detectLookalikeDomain(parsed.rootDomain);
        if (lookalike) {
            urlFlags.push("LOOKALIKE_DOMAIN");
            urlRisk = "malicious";
            findings.push({
                id: "URL_LOOKALIKE",
                title: "Brand Lookalike Domain Detected",
                explanation: lookalike.description,
                evidence: parsed.rootDomain,
                severity: "CRITICAL",
                source: "URL",
                confidence: 95,
                status: "confirmed"
            });
        }

        // Check 3: Deceptive Subdomain
        if (parsed.host !== parsed.rootDomain && !parsed.isIp) {
            for (const brand of Object.keys(TARGETED_BRANDS)) {
                if (parsed.host.startsWith(brand + ".") || parsed.host.includes("." + brand + ".")) {
                    if (!TARGETED_BRANDS[brand].includes(parsed.rootDomain)) {
                        urlFlags.push("DECEPTIVE_SUBDOMAIN");
                        urlRisk = "malicious";
                        findings.push({
                            id: "URL_DECEPTIVE_SUBDOMAIN",
                            title: "Deceptive Brand Subdomain",
                            explanation: `Hostname '${parsed.host}' uses '${brand}' as a subdomain, but the actual destination domain is '${parsed.rootDomain}'.`,
                            evidence: parsed.host,
                            severity: "CRITICAL",
                            source: "URL",
                            confidence: 95,
                            status: "confirmed"
                        });
                        break;
                    }
                }
            }
        }

        // Check 4: Disposable / High-Risk TLD
        if (HIGH_RISK_TLDS.has(parsed.tld)) {
            urlFlags.push("HIGH_RISK_TLD");
            if (urlRisk === "safe") urlRisk = "suspicious";
            findings.push({
                id: "URL_HIGH_RISK_TLD",
                title: "High-Risk Disposable Top-Level Domain",
                explanation: `Link points to a disposable or high-abuse top-level domain (.${parsed.tld}).`,
                evidence: parsed.rootDomain,
                severity: "MEDIUM",
                source: "URL",
                confidence: 70,
                status: "suspicious"
            });
        }

        // Check 5: URL Shortener concealing destination
        if (KNOWN_SHORTENERS.has(parsed.rootDomain)) {
            urlFlags.push("URL_SHORTENER");
            if (urlRisk === "safe") urlRisk = "suspicious";
            findings.push({
                id: "URL_SHORTENER_PRESENT",
                title: "Concealed URL Shortener Link",
                explanation: `Contains shortened link (${parsed.host}) that obscures the actual destination.`,
                evidence: rawHref,
                severity: "LOW",
                source: "URL",
                confidence: 75,
                status: "suspicious"
            });
        }

        // Check 6: Anchor Text vs Destination Mismatch
        if (anchorText && isDisplayingDomainOrUrl(anchorText)) {
            const anchorDomain = parseDomain(anchorText);
            if (anchorDomain.rootDomain && anchorDomain.tld && anchorDomain.rootDomain !== parsed.rootDomain) {
                const isAffiliated = (anchorDomain.sld && anchorDomain.sld === parsed.sld) ||
                    Object.values(TARGETED_BRANDS).some(domains => 
                        domains.includes(anchorDomain.rootDomain) && domains.includes(parsed.rootDomain)
                    );

                if (!isAffiliated) {
                    urlFlags.push("MISMATCHED_ANCHOR_TEXT");
                    urlRisk = "malicious";
                    findings.push({
                        id: "URL_MISMATCHED_ANCHOR",
                        title: "Misleading Displayed Link Text",
                        explanation: `Displayed link text indicates '${anchorDomain.rootDomain}', but the actual link destination points to '${parsed.rootDomain}'.`,
                        evidence: `Text: ${anchorText} -> Href: ${rawHref}`,
                        severity: "HIGH",
                        source: "URL",
                        confidence: 95,
                        status: "confirmed"
                    });
                }
            }
        }

        // Check 7: Insecure HTTP for sensitive operations
        const isStandardSchema = parsed.rootDomain && (
            parsed.rootDomain === "w3.org" ||
            parsed.rootDomain === "schema.org" ||
            parsed.rootDomain === "openxmlformats.org" ||
            parsed.rootDomain === "microsoft.com"
        );
        if (!isStandardSchema && rawHref.startsWith("http://") && (textContext.toLowerCase().includes("login") || textContext.toLowerCase().includes("verify password") || textContext.toLowerCase().includes("enter credentials") || textContext.toLowerCase().includes("verify your account"))) {
            urlFlags.push("INSECURE_HTTP_LOGIN");
            findings.push({
                id: "URL_INSECURE_HTTP",
                title: "Unencrypted HTTP Link for Sensitive Action",
                explanation: `Link requesting authentication or account verification uses unencrypted HTTP instead of HTTPS.`,
                evidence: rawHref,
                severity: "MEDIUM",
                source: "URL",
                confidence: 80,
                status: "suspicious"
            });
        }

        analyzedUrls.push({
            url: rawHref,
            domain: parsed.host,
            rootDomain: parsed.rootDomain,
            isIp: parsed.isIp,
            isShortener: KNOWN_SHORTENERS.has(parsed.rootDomain),
            isLookalike: Boolean(lookalike),
            reputation: urlRisk,
            flags: urlFlags
        });
    }

    return { findings, analyzedUrls };
}

// =========================================================================
// 3. LAYER C: SENDER & EMAIL AUTHENTICATION ANALYZER
// =========================================================================

function analyzeSenderAndAuth(fromHeader, replyToHeader, authData = {}, textContext = "") {
    const findings = [];
    const textLower = textContext.toLowerCase();

    // Extract display name and email address
    let displayName = "";
    let senderEmail = "";
    if (fromHeader) {
        const match = fromHeader.match(/^(?:["']?([^"']*)["']?\s*)?<([^>]+)>/);
        if (match) {
            displayName = (match[1] || "").trim();
            senderEmail = (match[2] || "").trim();
        } else if (fromHeader.includes("@")) {
            senderEmail = fromHeader.trim();
        } else {
            displayName = fromHeader.trim();
        }
    }

    const senderDomain = parseDomain(senderEmail);

    // Check 1: Display Name Impersonation
    if (displayName && senderDomain.rootDomain) {
        const cleanName = displayName.toLowerCase();
        for (const [brand, validDomains] of Object.entries(TARGETED_BRANDS)) {
            if (cleanName.includes(brand) && !validDomains.includes(senderDomain.rootDomain)) {
                // If sender claims to be Google, SBI, PayPal, etc. but sends from an external domain or free webmail
                findings.push({
                    id: "SENDER_BRAND_IMPERSONATION",
                    title: "Display Name Brand Impersonation",
                    explanation: `Sender display name claims to represent '${displayName}', but the email address is sent from an unrelated domain '${senderDomain.rootDomain}'.`,
                    evidence: `From: "${displayName}" <${senderEmail}>`,
                    severity: "HIGH",
                    source: "SENDER",
                    confidence: 90,
                    status: "confirmed"
                });
                break;
            }
        }
    }

    // Check 2: From vs Reply-To Inconsistency
    let replyToDomain = null;
    if (replyToHeader) {
        let replyEmail = replyToHeader;
        const match = replyToHeader.match(/<([^>]+)>/);
        if (match) replyEmail = match[1];
        replyToDomain = parseDomain(replyEmail);

        if (replyToDomain.rootDomain && senderDomain.rootDomain && replyToDomain.rootDomain !== senderDomain.rootDomain) {
            const isSameOrg = (senderDomain.sld && senderDomain.sld === replyToDomain.sld) ||
                Object.values(TARGETED_BRANDS).some(domains => 
                    domains.includes(senderDomain.rootDomain) && domains.includes(replyToDomain.rootDomain)
                );

            if (!isSameOrg) {
                const hasSensitiveIntent = (
                    textLower.includes("password") ||
                    textLower.includes("credentials") ||
                    textLower.includes("banking") ||
                    textLower.includes("wire transfer") ||
                    textLower.includes("suspended") ||
                    textLower.includes("urgent action required")
                );

                if (hasSensitiveIntent) {
                    findings.push({
                        id: "SENDER_REPLY_TO_MISMATCH",
                        title: "Suspicious Reply-To Address Mismatch",
                        explanation: `Replies are routed to '${replyToDomain.rootDomain}', which does not match the sender domain '${senderDomain.rootDomain}'.`,
                        evidence: `From: ${senderDomain.rootDomain} | Reply-To: ${replyToDomain.rootDomain}`,
                        severity: "MEDIUM",
                        source: "SENDER",
                        confidence: 80,
                        status: "suspicious"
                    });
                }
            }
        }
    }

    // Check 3: Cryptographic Authentication (SPF, DKIM, DMARC)
    const spf = String(authData.spf || "none").toLowerCase();
    const dkim = String(authData.dkim || "none").toLowerCase();
    const dmarc = String(authData.dmarc || "none").toLowerCase();

    if (spf === "fail" || spf === "softfail" || spf === "permerror" || dkim === "fail" || dmarc === "fail") {
        findings.push({
            id: "AUTH_FAILURE",
            title: "Email Security Authentication Failed",
            explanation: `Message failed sender domain validation checks (SPF: ${spf}, DKIM: ${dkim}, DMARC: ${dmarc}).`,
            evidence: `SPF: ${spf}, DKIM: ${dkim}, DMARC: ${dmarc}`,
            severity: "HIGH",
            source: "SENDER",
            confidence: 90,
            status: "confirmed"
        });
    }

    return {
        findings,
        senderSummary: {
            sender: senderEmail,
            domain: senderDomain.rootDomain,
            displayName,
            spf,
            dkim,
            dmarc,
            alignment: findings.some(f => f.id === "SENDER_BRAND_IMPERSONATION") ? "IMPERSONATION" : "ALIGNED"
        }
    };
}

// =========================================================================
// 4. LAYER A: MESSAGE-CONTENT CONTEXTUAL ANALYZER
// =========================================================================

function analyzeContent(subject = "", body = "", source = "EMAIL", urlFindings = []) {
    const findings = [];
    const text = `${subject} ${body}`.trim();
    const textLower = text.toLowerCase();

    if (!text) {
        return { findings, isAwarenessOrDiscussion: false };
    }

    // A. Detect Educational / Security Awareness Context (Anti-False-Positive Guard)
    // E.g., "Beware of fraud", "Security tip: We never ask for your password", "Phishing awareness training"
    const isAwarenessOrDiscussion = (
        (textLower.includes("beware of") || textLower.includes("never share your") || textLower.includes("will never ask") ||
         textLower.includes("security tips") || textLower.includes("awareness") || textLower.includes("fraud alert: do not")) &&
        !urlFindings.some(f => f.severity === "CRITICAL" || f.severity === "HIGH")
    );

    if (isAwarenessOrDiscussion) {
        findings.push({
            id: "CONTENT_AWARENESS_BENIGN",
            title: "Security Advisory / Awareness Context",
            explanation: "Message discusses security risks or warns recipients against sharing confidential credentials.",
            evidence: "Contextual anti-phishing advisory phrases detected",
            severity: "INFO",
            source: "CONTENT",
            confidence: 85,
            status: "confirmed"
        });
        return { findings, isAwarenessOrDiscussion: true };
    }

    // B. Account Suspension / Deletion / Urgent Threat
    const hasAccountThreatWord = /(account|profile|access|service|membership|card|sim|kyc|netbanking|banking)\b/.test(textLower);
    const hasDeactivationAction = /(suspended|deactivated|terminated|blocked|disabled|closed|locked|expire|cancelled|restricted|hold|compromised|frozen|action required)/.test(textLower);
    const hasUrgentTimeframe = /(within (?:24|12|48|2|1) (?:hours|hrs)|immediately|today|urgent|urgent action|final notice|final warning|last reminder|now)/.test(textLower);

    if (hasAccountThreatWord && hasDeactivationAction && hasUrgentTimeframe) {
        findings.push({
            id: "CONTENT_URGENT_ACCOUNT_THREAT",
            title: "Urgent Account Suspension Threat",
            explanation: "Pressures recipient with immediate account closure or suspension unless rapid action is taken.",
            evidence: text.match(/(?:account|access|service|card|sim|kyc|banking).{0,40}(?:suspended|deactivated|terminated|blocked|closed|restricted|locked).{0,40}(?:within \d+ hours|immediately|today|final warning|urgent)/i)?.[0] || "Account threat with immediate deadline",
            severity: "HIGH",
            source: "CONTENT",
            confidence: 85,
            status: "confirmed"
        });
    }

    // C. Credential / OTP Solicitation
    const hasDoNotShareOtp = /(?:do not|dont|don't|never|pls do not|please do not|bank never|never calls? to)\s+(?:share|disclose|reveal|give|tell|ask for)\s+(?:your\s+|the\s+|this\s+|it\s+)?(?:[a-z0-9/,\s]{0,20})?(?:otp|password|pin|credentials|passcode|cvv|mpin)/i.test(textLower)
        || /(?:never|do not|don't)\s+share\s+it\s+with\s+anyone/i.test(textLower)
        || /never\s+share\s+(?:otp|pin|card)/i.test(textLower)
        || /do not share (?:your\s+|the\s+|this\s+)?otp/i.test(textLower);

    const isBenignOtp = /(?:is your (?:otp|verification code|one time password|security code|login code)|(?:your )?otp (?:for [^.]+? )?is \d+|\b\d{4,8} is (?:your |the )?(?:otp|code)|use (?:otp )?\d{4,8}|verification code is \d+|security code is \d+|one time password|otp:\s*\d{4,8}|\d{4,8}\s*is\s*your\s*verification\s*otp)/i.test(textLower);
    const hasCredentialDemand = !hasDoNotShareOtp && (
        /(?:reply with|send|email|forward)\s+(?:us\s+|me\s+|to\s+)?(?:your\s+|the\s+)?(?:[a-z0-9\s,]{0,15})?(?:password|pin|otp|passcode|secret code|credentials|cvv|seed phrase)/i.test(textLower) ||
        (!isBenignOtp && /(?:enter|provide|confirm|verify|share)\s+(?:us\s+|me\s+)?(?:your\s+|the\s+)?(?:[a-z0-9\s,]{0,15})?(?:password|pin|passcode|secret code|credentials|cvv|seed phrase)/i.test(textLower)) ||
        (!isBenignOtp && /(?:share|tell|disclose)\s+(?:us\s+|me\s+)?(?:your\s+|the\s+)?(?:[a-z0-9\s,]{0,15})?otp/i.test(textLower))
    );
    if (hasCredentialDemand) {
        findings.push({
            id: "CONTENT_CREDENTIAL_SOLICITATION",
            title: "Direct Credential / OTP Solicitation",
            explanation: "Directly requests confidential passwords, PINs, OTP codes, or secret authentication keys.",
            evidence: text.match(/(?:reply with|send|enter|provide|confirm|verify|share).{0,35}(?:password|pin|otp|passcode|secret code|credentials|cvv)/i)?.[0] || "Solicitation of confidential security codes",
            severity: "CRITICAL",
            source: "CONTENT",
            confidence: 95,
            status: "confirmed"
        });
    }

    // D. Financial & UPI Scams / Fraudulent Refunds / Lottery Claims
    const hasUpiOrRefund = /(refund of|cashback of|receive money|collect request|approve request|upi pin to receive|scan qr to receive)/.test(textLower);
    const hasMoneyAmount = /(inr|rs\.?|₹|\$|usd|eur)\s*[\d,]+|\b(crore|lakh|50000|100000|lottery|prize money)\b/.test(textLower);
    if (hasUpiOrRefund && hasMoneyAmount) {
        findings.push({
            id: "CONTENT_FINANCIAL_REFUND_SCAM",
            title: "Fraudulent UPI / Payment Refund Lure",
            explanation: "Claims incoming refund or prize money requiring approval or PIN entry (classic UPI reverse-payment scam).",
            evidence: text.match(/(?:refund|cashback|receive money|collect request|lottery).{0,35}(?:inr|rs|₹|\$|crore|lakh|\d+)/i)?.[0] || "Fraudulent refund or prize transfer solicitation",
            severity: "CRITICAL",
            source: "CONTENT",
            confidence: 90,
            status: "confirmed"
        });
    }

    // E. Fake Job / Upfront Processing Fee Scam
    const hasJobOffer = /(job offer|appointment letter|work from home|data entry job|part time job|internship offer)/.test(textLower);
    const hasUpfrontFee = /(registration fee|processing fee|security deposit|refundable deposit|training fee|pay rs|pay inr)/.test(textLower);
    if (hasJobOffer && hasUpfrontFee) {
        findings.push({
            id: "CONTENT_JOB_FEE_SCAM",
            title: "Fraudulent Job Offer with Upfront Fee",
            explanation: "Offers employment or internship opportunities while demanding an upfront registration, deposit, or processing fee.",
            evidence: "Employment lure combined with upfront fee request",
            severity: "HIGH",
            source: "CONTENT",
            confidence: 90,
            status: "confirmed"
        });
    }

    // F. Delivery & Package Fee Smishing
    const hasDeliveryContext = /(package|parcel|shipment|courier|delivery|fedex|dhl|usps|indiapost|india post)/.test(textLower);
    const hasDeliveryIssue = /(incomplete address|wrong address|update (?:your )?address|held|reschedule|unpaid (?:fee|redelivery)|pay (?:customs|redelivery|delivery)? fee|customs duty)/.test(textLower);
    if (hasDeliveryContext && hasDeliveryIssue) {
        const hasShortenerOrUntrustedLink = urlFindings.some(f => f.id === "URL_SHORTENER_PRESENT" || f.id === "URL_HIGH_RISK_TLD" || f.id === "URL_LOOKALIKE");
        findings.push({
            id: "CONTENT_DELIVERY_SCAM",
            title: "Package Delivery / Redelivery Fee Scam",
            explanation: "Falsely claims an undelivered parcel or held shipment to solicit fee payments or address updates.",
            evidence: text.match(/(?:package|parcel|shipment|courier|post).{0,40}(?:address|held|fee|unpaid)/i)?.[0] || "Fake parcel delivery notice",
            severity: hasShortenerOrUntrustedLink ? "CRITICAL" : "HIGH",
            source: "CONTENT",
            confidence: 90,
            status: "confirmed"
        });
    }

    // G. Remote Access Software Request
    const hasRemoteAccessApp = /\b(anydesk|teamviewer|rustdesk|quicksupport|ultraviewer)\b/.test(textLower);
    const hasInstallAction = /(install|download|give code|share 9-digit|allow access|remote support)/.test(textLower);
    if (hasRemoteAccessApp && hasInstallAction) {
        findings.push({
            id: "CONTENT_REMOTE_ACCESS_FRAUD",
            title: "Remote Access Software Installation Request",
            explanation: "Instructs recipient to install remote-desktop software (AnyDesk, TeamViewer) that enables complete device takeover.",
            evidence: text.match(/(?:install|download|share|allow).{0,25}(?:anydesk|teamviewer|rustdesk|quicksupport)/i)?.[0] || "Remote access software request",
            severity: "CRITICAL",
            source: "CONTENT",
            confidence: 95,
            status: "confirmed"
        });
    }

    // H. Unsolicited Billing Adjustment / Transaction Review Phishing Lure
    const hasBillingAdjustment = /(?:identified an adjustment|adjustment associated with|unauthorized (?:charge|payment|transaction)|review the transaction details|confirm (?:the )?(?:transaction|information)|unsolicited (?:invoice|billing)|recent payment)/i.test(textLower);
    const hasGenericBillingSender = /(?:billing department|accounting team|payment center|invoice support|billing system)/i.test(textLower);
    const hasViewTransactionLink = /(?:view transaction|review transaction|view invoice|check payment|confirm payment|view payment)/i.test(textLower);

    if ((hasBillingAdjustment && (hasViewTransactionLink || hasGenericBillingSender)) || (hasGenericBillingSender && hasViewTransactionLink)) {
        findings.push({
            id: "CONTENT_UNSOLICITED_TRANSACTION_LURE",
            title: "Unsolicited Billing Adjustment / Transaction Review Lure",
            explanation: "Claims an unexpected payment adjustment or asks to review unverified transaction details without specific invoice or merchant information.",
            evidence: text.match(/(?:identified an adjustment|adjustment associated with|review the transaction|confirm the information|view transaction|billing department|billing system).{0,50}/i)?.[0] || "Unsolicited payment adjustment notice",
            severity: "HIGH",
            source: "CONTENT",
            confidence: 85,
            status: "confirmed"
        });
    }

    // I. Cryptocurrency Extortion / Webcam Blackmail
    const hasExtortionThreat = /(recorded you|webcam|pegasus|spyware|compromising video|masturbating|blackmail|intimate video|hacked your device|compromising)/i.test(textLower);
    const hasCryptoDemand = /(bitcoin|btc|wallet|crypto|cryptocurrency|send 0\.|to my wallet)/i.test(textLower);
    if (hasExtortionThreat && hasCryptoDemand) {
        findings.push({
            id: "CONTENT_CRYPTO_EXTORTION",
            title: "Cryptocurrency Extortion / Blackmail",
            explanation: "Demands cryptocurrency payment under threat of releasing compromising webcam recordings or personal surveillance data.",
            evidence: text.match(/(?:recorded you|pegasus|spyware|compromising|blackmail).{0,50}(?:bitcoin|btc|wallet|\d+ hours)/i)?.[0] || "Crypto extortion threat",
            severity: "CRITICAL",
            source: "CONTENT",
            confidence: 95,
            status: "confirmed",
            evidenceType: "CONTENT_MALICIOUS",
            dimension: "DIM_PAYMENT_FINANCIAL"
        });
    }

    // J. CEO / Executive Gift Card Fraud
    const hasGiftCard = /(gift card|apple gift|google play card|steam card|amazon gift card)/i.test(textLower);
    const hasPurchaseOrCodeDemand = /(scratch|purchase|buy \d+|at your desk|presentation|scratch the back|send pictures of the code|redemption code|urgent favor)/i.test(textLower);
    if (hasGiftCard && hasPurchaseOrCodeDemand) {
        findings.push({
            id: "CONTENT_GIFT_CARD_FRAUD",
            title: "Executive Gift Card Fraud Lure",
            explanation: "Solicits urgent purchase of gift cards and demands redemption codes, characteristic of business executive impersonation fraud.",
            evidence: text.match(/(?:gift card|purchase|buy \d+|scratch).{0,50}(?:apple|code|desk|favor|redemption)/i)?.[0] || "Gift card purchase solicitation",
            severity: "CRITICAL",
            source: "CONTENT",
            confidence: 95,
            status: "confirmed",
            evidenceType: "CONTENT_MALICIOUS",
            dimension: "DIM_PAYMENT_FINANCIAL"
        });
    }

    // K. Law Enforcement / Arrest Warrant Extortion
    const hasPoliceOrWarrant = /(arrest warrant|federal police|police bureau|police custody|criminal tax evasion|law enforcement|court order|court summons|cyber crime cell)/i.test(textLower);
    const hasFineOrSettlement = /(settlement fee|settlement fine|avoid arrest|pay the settlement|fine of|police custody|custody)/i.test(textLower);
    if (hasPoliceOrWarrant && hasFineOrSettlement) {
        findings.push({
            id: "CONTENT_LAW_ENFORCEMENT_EXTORTION",
            title: "Law Enforcement Arrest Extortion",
            explanation: "Falsely threatens immediate arrest or legal custody unless an unverified settlement fee or fine is paid.",
            evidence: text.match(/(?:arrest warrant|police|court|summons|criminal).{0,50}(?:settlement|avoid arrest|custody|fine)/i)?.[0] || "Law enforcement arrest threat",
            severity: "CRITICAL",
            source: "CONTENT",
            confidence: 95,
            status: "confirmed",
            evidenceType: "CONTENT_MALICIOUS",
            dimension: "DIM_COERCION_URGENCY"
        });
    }

    // L. Phone Callback Vishing Lure
    const hasCallPrompt = /(?:call our|call us|call support|call toll free|reach us at|call)\s+(?:toll free\s+|immediately\s+)?(?:support\s+)?(?:at\s+)?(?:\+?1?-?[0-9]{3}-?[0-9]{3}-?[0-9]{4}|\+?[0-9]{10,13})/i.test(textLower) ||
        ((textLower.includes("call our toll free") || textLower.includes("call our support") || textLower.includes("call")) && /\+?1?[-.]?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}/.test(textLower));
    const hasFakeInvoiceOrCharge = /(charged you|auto-renewal|annual subscription|did not authorize|geek squad|mcafee|norton|invoice for your|\$499)/i.test(textLower);
    if (hasCallPrompt && hasFakeInvoiceOrCharge) {
        findings.push({
            id: "CONTENT_PHONE_CALLBACK_PHISHING",
            title: "Phone Callback Vishing Lure",
            explanation: "Presents a fraudulent auto-renewal charge or invoice and instructs recipient to call a fake support number to cancel (vishing).",
            evidence: text.match(/(?:charged|subscription|renewed|invoice).{0,50}(?:call|toll free|\+\d+)/i)?.[0] || "Phone callback vishing prompt",
            severity: "HIGH",
            source: "CONTENT",
            confidence: 90,
            status: "confirmed",
            evidenceType: "CONTENT_MALICIOUS",
            dimension: "DIM_COERCION_URGENCY"
        });
    }

    // H. Commercial / Unsolicited Marketing (Spam signals)
    const hasMarketingKeywords = (
        textLower.includes("clearance sale") ||
        textLower.includes("flat off") ||
        textLower.includes("exclusive discount") ||
        textLower.includes("use coupon code") ||
        textLower.includes("limited time deal") ||
        (textLower.includes("unsubscribe") && textLower.includes("discount"))
    );
    if (hasMarketingKeywords && findings.length === 0) {
        findings.push({
            id: "CONTENT_MARKETING_SPAM",
            title: "Unsolicited Promotional Content",
            explanation: "Contains promotional marketing materials, discount offers, or mass-broadcast advertising.",
            evidence: "Commercial marketing offers or sale keywords",
            severity: "LOW",
            source: "CONTENT",
            confidence: 80,
            status: "confirmed"
        });
    }

    return { findings, isAwarenessOrDiscussion: false };
}

// =========================================================================
// 5. LAYER D: SMS-SPECIFIC HEURISTICS
// =========================================================================

function analyzeSmsSpecifics(sender, body, urlFindings) {
    const findings = [];
    const textLower = body.toLowerCase();
    const senderClean = String(sender || "").trim();

    // Check 1: Fake Bank / KYC SMS Sender ID Spoofing
    // Indian / International alphanumeric headers often look like "VK-SBIINB", "AD-HDFCBK"
    const hasBankSenderPattern = /^[A-Z]{2}-[A-Z0-9]{5,8}$/i.test(senderClean);
    const hasKycOrPanAlert = /(kyc|pan card|aadhaar|sim block|debit card block|account blocked)/.test(textLower);
    const hasLink = urlFindings.length > 0;

    if (hasKycOrPanAlert && hasLink) {
        findings.push({
            id: "SMS_KYC_SIM_DEACTIVATION",
            title: "SMS KYC / Account Deactivation Smishing",
            explanation: "Urgent SMS claiming bank account, SIM card, or KYC will be blocked, directing to an unverified external link.",
            evidence: `Sender: ${senderClean} | Lure: KYC / Account block`,
            severity: "CRITICAL",
            source: "SMS",
            confidence: 90,
            status: "confirmed"
        });
    }

    // Check 2: Personal Phone Number Sending Banking / OTP Notices
    const isPersonalPhoneNumber = /^\+?[0-9]{10,13}$/.test(senderClean.replace(/[\s-]/g, ""));
    const mentionsOfficialInstitution = /(bank|otp|income tax|customs|fedex|dhl|post|india post|courier|delivery|police|court|lottery|kyc)/.test(textLower);
    if (isPersonalPhoneNumber && mentionsOfficialInstitution && (hasLink || textLower.includes("call") || textLower.includes("held"))) {
        findings.push({
            id: "SMS_PERSONAL_NUMBER_INSTITUTION_SPOOF",
            title: "Official Notification from Personal Mobile Number",
            explanation: "Official institution or bank notices are sent from authorized enterprise headers, not personal mobile phone numbers.",
            evidence: `Sender mobile number: ${senderClean}`,
            severity: "HIGH",
            source: "SMS",
            confidence: 85,
            status: "confirmed"
        });
    }

    return findings;
}

// =========================================================================
// 6. CENTRAL EVIDENCE COMBINER & SCORE CALCULATOR
// =========================================================================

/**
 * Combines structured findings into a calibrated Risk Score (0-100) and Verdict.
 * HIGHER SCORE = MORE DANGEROUS.
 */
function calculateVerdictsAndScores(allFindings, isAwareness) {
    if (isAwareness) {
        return {
            verdict: "Likely safe",
            riskScore: 5,
            category: "LEGITIMATE",
            confidence: 90
        };
    }

    if (allFindings.length === 0) {
        return {
            verdict: "Likely safe",
            riskScore: 10,
            category: "LEGITIMATE",
            confidence: 80
        };
    }

    let baseRiskScore = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const f of allFindings) {
        switch (f.severity) {
            case "CRITICAL":
                criticalCount++;
                break;
            case "HIGH":
                highCount++;
                break;
            case "MEDIUM":
                mediumCount++;
                break;
            case "LOW":
                lowCount++;
                break;
            default:
                break;
        }
    }

    // Layered Non-Additive Weighting (avoids simple linear inflation)
    if (criticalCount > 0) {
        // Any confirmed critical signal (credential harvesting, remote access, lookalike link) immediately places in High Risk band (70-100)
        baseRiskScore = 80 + Math.min(18, (criticalCount - 1) * 6 + highCount * 4);
    } else if (highCount > 0) {
        if (highCount >= 2) {
            baseRiskScore = 72 + Math.min(15, (highCount - 2) * 5 + mediumCount * 3);
        } else {
            // Single high finding starts in upper Suspicious band (55-68)
            baseRiskScore = 58 + Math.min(10, mediumCount * 4);
        }
    } else if (mediumCount > 0) {
        baseRiskScore = 32 + Math.min(25, (mediumCount - 1) * 8 + lowCount * 3);
    } else if (lowCount > 0) {
        baseRiskScore = 22 + Math.min(12, (lowCount - 1) * 4);
    } else {
        baseRiskScore = 12;
    }

    const finalRiskScore = Math.max(0, Math.min(100, Math.round(baseRiskScore)));

    // Determine Verdict based on strict bands
    let verdict = "Likely safe";
    let category = "LEGITIMATE";

    if (finalRiskScore >= 70) {
        verdict = "High risk";
        category = "PHISHING";
    } else if (finalRiskScore >= 40) {
        verdict = "Suspicious";
        category = "NEEDS REVIEW";
    } else if (finalRiskScore >= 20) {
        verdict = "Needs caution";
        category = "SPAM";
    } else {
        verdict = "Likely safe";
        category = "LEGITIMATE";
    }

    return {
        verdict,
        riskScore: finalRiskScore,
        category,
        confidence: Math.min(95, 75 + criticalCount * 8 + highCount * 5)
    };
}

function generateRecommendations(verdict, findings) {
    const actions = [];
    const findingIds = new Set(findings.map(f => f.id));

    if (findingIds.has("CONTENT_CREDENTIAL_SOLICITATION")) {
        actions.push("Never reply with or disclose passwords, OTPs, or authentication PINs to any requester.");
    }
    if (findingIds.has("URL_LOOKALIKE") || findingIds.has("URL_DECEPTIVE_SUBDOMAIN") || findingIds.has("URL_MISMATCHED_ANCHOR")) {
        actions.push("Do not click or open the links in this message. The destination domain is deceptive.");
    }
    if (findingIds.has("CONTENT_FINANCIAL_REFUND_SCAM")) {
        actions.push("Do not approve UPI collection requests or enter your UPI PIN. Receiving money never requires a PIN.");
    }
    if (findingIds.has("CONTENT_REMOTE_ACCESS_FRAUD")) {
        actions.push("Do not install remote-support applications (AnyDesk, TeamViewer) or share connection codes.");
    }
    if (findingIds.has("CONTENT_DELIVERY_SCAM")) {
        actions.push("Check parcel status directly on the official courier website or app, not via text links.");
    }
    if (findingIds.has("SENDER_BRAND_IMPERSONATION")) {
        actions.push("Verify the sender's authentic contact details directly through their official service portal.");
    }

    if (actions.length === 0) {
        if (verdict === "High risk" || verdict === "Suspicious") {
            actions.push("Exercise extreme caution. Do not download attachments or follow links in this communication.");
        } else if (verdict === "Needs caution") {
            actions.push("Verify sender identity before replying or acting on promotional offers.");
        } else {
            actions.push("No immediate defensive action required. Message appears routine and benign.");
        }
    }

    return actions;
}

// =========================================================================
// 7. PRIMARY DETECTION PIPELINE INTERFACE
// =========================================================================

function ensureTaxonomy(f) {
    if (!f.dimension) {
        if (f.id.startsWith("AUTH_") || f.id.includes("SPF") || f.id.includes("DKIM") || f.id.includes("DMARC")) {
            f.dimension = "DIM_AUTHENTICATION";
        } else if (f.id.startsWith("URL_") || f.source === "URL") {
            f.dimension = "DIM_LINK_DESTINATION";
        } else if (f.id.startsWith("SENDER_") || f.source === "SENDER") {
            f.dimension = "DIM_SENDER_IDENTITY";
        } else if (f.id.includes("FINANCIAL") || f.id.includes("CRYPTO") || f.id.includes("REFUND") || f.id.includes("GIFT_CARD") || f.id.includes("TRANSACTION") || f.id.includes("FEE") || f.id.includes("PAYMENT")) {
            f.dimension = "DIM_PAYMENT_FINANCIAL";
        } else if (f.id.includes("URGENT") || f.id.includes("EXTORTION") || f.id.includes("COERCION") || f.id.includes("VISHING") || f.id.includes("CALLBACK") || f.id.includes("THREAT") || f.id.includes("LAW_ENFORCEMENT")) {
            f.dimension = "DIM_COERCION_URGENCY";
        } else {
            f.dimension = "DIM_CONTENT_INTENT";
        }
    }
    if (!f.evidenceType) {
        if (f.severity === "CRITICAL" || f.severity === "HIGH") {
            f.evidenceType = "CONTENT_MALICIOUS";
        } else if (f.severity === "MEDIUM") {
            f.evidenceType = "SUSPICIOUS_SIGNAL";
        } else if (f.severity === "INFO") {
            f.evidenceType = "BENIGN_INDICATOR";
        } else {
            f.evidenceType = "TECHNICAL_ANOMALY";
        }
    }
    return f;
}

/**
 * Evaluates any Gmail email or authorized SMS message.
 * Returns a fully structured, explainable security verdict.
 */
function analyzeMessage(messagePayload) {
    const {
        id = "msg_" + crypto.randomBytes(6).toString("hex"),
        source = "EMAIL",
        from = "",
        replyTo = "",
        subject = "",
        body = "",
        urls = [],
        auth = {},
        deviceId = null
    } = messagePayload || {};

    const text = `${subject} ${body}`.trim();

    // 1. URL Analysis
    const { findings: urlFindings, analyzedUrls } = analyzeUrls(urls, text);

    // 2. Sender Analysis (for Emails)
    const { findings: senderFindings, senderSummary } = analyzeSenderAndAuth(from, replyTo, auth, text);

    // 3. Content Analysis
    const { findings: contentFindings, isAwarenessOrDiscussion } = analyzeContent(subject, body, source, urlFindings);

    // 4. SMS Specifics
    let smsFindings = [];
    if (source === "SMS") {
        smsFindings = analyzeSmsSpecifics(from, body, urlFindings);
    }

    // Combine all structured findings
    const allFindings = [
        ...urlFindings,
        ...senderFindings,
        ...contentFindings,
        ...smsFindings
    ];

    // Deduplicate findings by ID
    const uniqueFindings = [];
    const seenFindingIds = new Set();
    for (const f of allFindings) {
        if (!seenFindingIds.has(f.id)) {
            seenFindingIds.add(f.id);
            uniqueFindings.push(ensureTaxonomy(f));
        }
    }

    // Calculate score and verdict
    const { verdict, riskScore, category, confidence } = calculateVerdictsAndScores(uniqueFindings, isAwarenessOrDiscussion);

    // Build human-readable explainable summary
    let summary = "";
    if (verdict === "High risk") {
        summary = `High risk detected. Identified ${uniqueFindings.length} critical or severe threat indicator(s) including deceptive lures or malicious link structures.`;
    } else if (verdict === "Suspicious") {
        summary = `Suspicious traits detected requiring verification. Message contains anomalous headers, unverified links, or urgent tone.`;
    } else if (verdict === "Needs caution") {
        summary = `Guarded communication. Contains marketing, unverified senders, or minor anomalies requiring user awareness.`;
    } else {
        summary = `Communication exhibits authentic patterns with no active threat signals or malicious indicators detected.`;
    }

    const recommendedActions = generateRecommendations(verdict, uniqueFindings);

    const analysisLimitations = [];
    if (source === "EMAIL" && (!auth.spf || auth.spf === "none") && (!auth.dkim || auth.dkim === "none")) {
        analysisLimitations.push("Cryptographic sender authentication headers (SPF/DKIM) were not present in message metadata.");
    }

    return {
        id,
        source: source.toUpperCase(),
        verdict,
        riskScore,
        category,
        confidence,
        summary,
        findings: uniqueFindings,
        urlAnalysis: analyzedUrls,
        senderAnalysis: senderSummary,
        reasons: uniqueFindings.map(f => f.explanation),
        evidence: uniqueFindings.map(f => ({ type: f.id, description: f.explanation, evidence: f.evidence })),
        recommendedActions,
        analysisLimitations,
        scannedAt: new Date().toISOString()
    };
}

// =========================================================================
// 8. THREAT INTELLIGENCE PROVIDER
// =========================================================================

const ThreatIntelligenceProvider = {
    async checkThreatIntelligence(targetUrl) {
        const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY || process.env.SAFE_BROWSING_API_KEY;
        if (!apiKey) {
            return {
                status: "UNAVAILABLE",
                provider: "Google Safe Browsing v4 (API key not configured)",
                isMalicious: false,
                threatType: null,
                checkedAt: new Date().toISOString(),
                details: "External threat intelligence is not configured. Reputation assessment reflects local deterministic and heuristic checks."
            };
        }

        try {
            const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;
            const payload = {
                client: {
                    clientId: "sentinel-ai-security",
                    clientVersion: "1.0.0"
                },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url: targetUrl }]
                }
            };

            const response = await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(3500)
            });

            if (!response.ok) {
                return {
                    status: "ERROR",
                    provider: "Google Safe Browsing v4",
                    isMalicious: false,
                    threatType: null,
                    checkedAt: new Date().toISOString(),
                    details: `Provider lookup returned HTTP status ${response.status}. Link evaluated through local structural heuristics.`
                };
            }

            const data = await response.json();
            if (data && data.matches && data.matches.length > 0) {
                const threatType = data.matches[0].threatType;
                return {
                    status: "CONFIRMED_THREAT",
                    provider: "Google Safe Browsing v4",
                    isMalicious: true,
                    threatType,
                    checkedAt: new Date().toISOString(),
                    details: `Confirmed malicious link flagged in threat database as ${threatType}.`
                };
            }

            return {
                status: "CLEAN",
                provider: "Google Safe Browsing v4",
                isMalicious: false,
                threatType: null,
                checkedAt: new Date().toISOString(),
                details: "No active threat record found in Google Safe Browsing database. Link must still be evaluated for lookalike or structural anomalies."
            };
        } catch (err) {
            return {
                status: "ERROR",
                provider: "Google Safe Browsing v4",
                isMalicious: false,
                threatType: null,
                checkedAt: new Date().toISOString(),
                details: `Lookup timed out or encountered network error: ${err.message}. Link evaluated through local structural heuristics.`
            };
        }
    }
};

// =========================================================================
// 9. DOMAIN INFORMATION PROVIDER (SAFE SERVER-SIDE DNS)
// =========================================================================

function isPrivateOrReservedIp(ipOrHost) {
    if (!ipOrHost || typeof ipOrHost !== "string") return false;
    const clean = ipOrHost.trim().toLowerCase();
    if (clean === "localhost" || clean === "::1" || clean === "0.0.0.0") return true;

    // IPv4 matching
    const parts = clean.split(".").map(Number);
    if (parts.length === 4 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
        if (parts[0] === 127) return true; // Loopback
        if (parts[0] === 10) return true; // Class A private
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // Class B private
        if (parts[0] === 192 && parts[1] === 168) return true; // Class C private
        if (parts[0] === 169 && parts[1] === 254) return true; // Link-local / AWS metadata
        if (parts[0] === 0) return true; // Default route
    }

    // IPv6 private / link-local / unique-local
    if (clean.startsWith("fc") || clean.startsWith("fd") || clean.startsWith("fe80")) return true;

    return false;
}

const DomainInformationProvider = {
    isPrivateOrReservedIp,
    async inspectDomain(host, protocol = "https:") {
        const cleanHost = String(host || "").trim().toLowerCase();
        const isInternal = isPrivateOrReservedIp(cleanHost);

        if (isInternal) {
            return {
                host: cleanHost,
                isInternalOrSsrf: true,
                ip: cleanHost,
                hasDns: false,
                hasMx: false,
                provider: "Local Network Defense",
                registrationInfo: "Internal / Private Network Space (Non-routable)",
                certificateInfo: "N/A (Local / Internal Destination)",
                retrievedAt: new Date().toISOString()
            };
        }

        let resolvedIp = null;
        let hasDns = false;
        let isReboundInternal = false;

        try {
            const lookupRes = await dns.promises.lookup(cleanHost);
            if (lookupRes && lookupRes.address) {
                resolvedIp = lookupRes.address;
                hasDns = true;
                if (isPrivateOrReservedIp(resolvedIp)) {
                    isReboundInternal = true;
                }
            }
        } catch (_) {
            hasDns = false;
        }

        let hasMx = false;
        let mxCount = 0;
        try {
            const mxRecords = await dns.promises.resolveMx(cleanHost);
            if (Array.isArray(mxRecords) && mxRecords.length > 0) {
                hasMx = true;
                mxCount = mxRecords.length;
            }
        } catch (_) {
            hasMx = false;
        }

        return {
            host: cleanHost,
            isInternalOrSsrf: isReboundInternal,
            ip: resolvedIp,
            hasDns,
            hasMx,
            mxCount,
            provider: "Server DNS Resolver",
            registrationInfo: "Unavailable (Direct registrar RDAP not queried to prevent rate limiting)",
            certificateInfo: protocol.toLowerCase() === "https:" ? "HTTPS Protocol Scheme Present" : "Unencrypted HTTP Scheme",
            retrievedAt: new Date().toISOString()
        };
    }
};

// =========================================================================
// 10. RISK SCORING SERVICE
// =========================================================================

const RiskScoringService = {
    calculateRiskScore(findings, isAwarenessOrDiscussion = false) {
        return calculateVerdictsAndScores(findings, isAwarenessOrDiscussion);
    }
};

// =========================================================================
// 11. URL ANALYSIS SERVICE
// =========================================================================

const URLAnalysisService = {
    validateUrl(inputUrl) {
        if (!inputUrl || typeof inputUrl !== "string") {
            return { valid: false, error: "Please enter a valid URL." };
        }
        const trimmed = inputUrl.trim();
        if (trimmed.length > 2048) {
            return { valid: false, error: "URL exceeds maximum permitted length of 2048 characters." };
        }

        let parsed;
        try {
            parsed = new URL(trimmed);
        } catch (_) {
            if (!trimmed.includes("://") && !trimmed.startsWith("javascript:") && !trimmed.startsWith("data:")) {
                try {
                    parsed = new URL("https://" + trimmed);
                } catch (e) {
                    return { valid: false, error: "Invalid URL syntax. Please enter a valid web address." };
                }
            } else {
                return { valid: false, error: "Invalid URL syntax. Please enter a valid web address." };
            }
        }

        const protocol = parsed.protocol.toLowerCase();
        if (protocol !== "http:" && protocol !== "https:") {
            return {
                valid: false,
                isDangerousScheme: true,
                protocol,
                error: `Unsupported scheme '${protocol}'. Only standard http: and https: web protocols are supported.`
            };
        }

        return { valid: true, parsedUrl: parsed, normalizedUrl: parsed.href };
    },

    async inspectUrl(inputUrl) {
        const validation = this.validateUrl(inputUrl);
        if (!validation.valid) {
            if (validation.isDangerousScheme) {
                const findings = [{
                    id: "UNSUPPORTED_SCHEME_DANGEROUS",
                    title: `Dangerous Scheme: ${validation.protocol}`,
                    explanation: `URL uses non-web protocol '${validation.protocol}' which can execute malicious scripts or exfiltrate credentials.`,
                    evidence: String(inputUrl).slice(0, 100),
                    severity: "CRITICAL",
                    source: "URL",
                    confidence: 100,
                    status: "confirmed"
                }];
                return {
                    isValid: false,
                    url: inputUrl,
                    normalizedUrl: inputUrl,
                    host: "",
                    rootDomain: "",
                    verdict: "High risk",
                    riskScore: 88,
                    category: "PHISHING",
                    confidence: 98,
                    summary: `Critical risk. The URL uses an unsupported, potentially dangerous scheme (${validation.protocol}).`,
                    findings,
                    urlStructure: { rawUrl: inputUrl, protocol: validation.protocol, host: "" },
                    threatIntelligence: { status: "UNCHECKED", provider: "None", details: "Unsupported scheme rejected before network lookups." },
                    domainInfo: { host: "", ip: null, hasDns: false, registrationInfo: "Unavailable", certificateInfo: "N/A" },
                    recommendedActions: [
                        "Never open links beginning with javascript:, data:, or file:.",
                        "Block and report the sender requesting you open this link."
                    ],
                    analysisLimitations: ["Rejected before network lookup due to dangerous scheme."],
                    scannedAt: new Date().toISOString()
                };
            }

            return {
                isValid: false,
                url: inputUrl,
                normalizedUrl: inputUrl,
                host: "",
                rootDomain: "",
                verdict: "Suspicious",
                riskScore: 50,
                category: "SUSPICIOUS",
                confidence: 70,
                summary: validation.error || "The URL syntax is invalid or unsupported.",
                findings: [{
                    id: "MALFORMED_URL_SYNTAX",
                    title: "Malformed or Invalid URL",
                    explanation: validation.error || "Cannot parse address into valid hostname and scheme.",
                    evidence: String(inputUrl).slice(0, 100),
                    severity: "MEDIUM",
                    source: "URL",
                    confidence: 80,
                    status: "confirmed"
                }],
                urlStructure: { rawUrl: inputUrl, protocol: "", host: "" },
                threatIntelligence: { status: "UNCHECKED", provider: "None", details: "Invalid URL rejected before lookup." },
                domainInfo: { host: "", ip: null, hasDns: false, registrationInfo: "Unavailable", certificateInfo: "N/A" },
                recommendedActions: ["Verify the link syntax before clicking."],
                analysisLimitations: ["Cannot perform DNS or reputation checks on malformed input."],
                scannedAt: new Date().toISOString()
            };
        }

        const { parsedUrl, normalizedUrl } = validation;
        const rawUrl = String(inputUrl).trim();
        const host = parsedUrl.hostname.toLowerCase();
        const protocol = parsedUrl.protocol.toLowerCase();

        // SSRF and Internal IP Protection
        if (isPrivateOrReservedIp(host)) {
            const findings = [{
                id: "SSRF_PRIVATE_NETWORK_BLOCKED",
                title: "Internal / Private IP Destination Blocked",
                explanation: `Target host '${host}' is in private or link-local address space (SSRF protection triggered).`,
                evidence: host,
                severity: "CRITICAL",
                source: "URL",
                confidence: 100,
                status: "confirmed"
            }];
            return {
                isValid: false,
                url: rawUrl,
                normalizedUrl,
                host,
                rootDomain: host,
                verdict: "High risk",
                riskScore: 92,
                category: "PHISHING",
                confidence: 100,
                summary: "Critical risk. Link targets private or internal network infrastructure.",
                findings,
                urlStructure: { rawUrl, normalizedUrl, protocol, host, rootDomain: host, isIp: true },
                threatIntelligence: { status: "BLOCKED", provider: "SSRF Guard", details: "Lookup aborted for private IP space." },
                domainInfo: { host, ip: host, hasDns: false, registrationInfo: "Private Network Space", certificateInfo: "N/A" },
                recommendedActions: [
                    "Do not click this link. Attackers use internal URLs to scan private networks or access cloud metadata."
                ],
                analysisLimitations: ["Internal/private network lookups are strictly prohibited."],
                scannedAt: new Date().toISOString()
            };
        }

        const parsedDomain = parseDomain(rawUrl);
        const findings = [];
        const urlStructure = {
            rawUrl,
            normalizedUrl,
            protocol,
            host,
            rootDomain: parsedDomain.rootDomain,
            sld: parsedDomain.sld,
            tld: parsedDomain.tld,
            isIp: parsedDomain.isIp,
            hasPort: Boolean(parsedUrl.port && parsedUrl.port !== "80" && parsedUrl.port !== "443"),
            port: parsedUrl.port || (protocol === "https:" ? "443" : "80"),
            pathname: parsedUrl.pathname,
            search: parsedUrl.search
        };

        // 1. Raw IP
        if (parsedDomain.isIp) {
            findings.push({
                id: "URL_RAW_IP",
                title: "Raw IP Address Destination",
                explanation: `Link destination uses a raw IP address (${host}) instead of a registered domain name.`,
                evidence: rawUrl,
                severity: "HIGH",
                source: "URL",
                confidence: 90,
                status: "confirmed"
            });
        }

        // 2. Lookalike domain
        const lookalike = detectLookalikeDomain(parsedDomain.rootDomain);
        if (lookalike) {
            findings.push({
                id: "URL_LOOKALIKE_DOMAIN",
                title: "Lookalike / Impersonated Domain",
                explanation: lookalike.description,
                evidence: parsedDomain.rootDomain,
                severity: "CRITICAL",
                source: "URL",
                confidence: 95,
                status: "confirmed"
            });
        }

        // 3. Deceptive Subdomain
        const hostParts = host.split(".");
        if (hostParts.length >= 3) {
            const subdomains = hostParts.slice(0, -2);
            for (const [brand] of Object.entries(TARGETED_BRANDS)) {
                if (subdomains.some(s => s === brand || s.includes(brand)) && !parsedDomain.rootDomain.includes(brand)) {
                    findings.push({
                        id: "URL_DECEPTIVE_SUBDOMAIN",
                        title: "Deceptive Brand Subdomain",
                        explanation: `Subdomain mimics authentic brand '${brand}' while actual destination is '${parsedDomain.rootDomain}'.`,
                        evidence: host,
                        severity: "CRITICAL",
                        source: "URL",
                        confidence: 95,
                        status: "confirmed"
                    });
                    break;
                }
            }
        }

        // 4. Punycode / IDN
        if (host.includes("xn--")) {
            findings.push({
                id: "URL_PUNYCODE_HOMOGLYPH",
                title: "Punycode / Homoglyph Domain",
                explanation: `Hostname uses Punycode encoding (${host}) which can conceal visually identical spoofed characters.`,
                evidence: host,
                severity: "HIGH",
                source: "URL",
                confidence: 85,
                status: "suspicious"
            });
        }

        // 5. High-Risk TLD
        if (HIGH_RISK_TLDS.has(parsedDomain.tld)) {
            findings.push({
                id: "URL_HIGH_RISK_TLD",
                title: "High-Risk Top-Level Domain",
                explanation: `Link uses disposable or abuse-prone top-level domain (.${parsedDomain.tld}).`,
                evidence: `.${parsedDomain.tld}`,
                severity: "MEDIUM",
                source: "URL",
                confidence: 75,
                status: "suspicious"
            });
        }

        // 6. URL Shortener
        if (KNOWN_SHORTENERS.has(host) || KNOWN_SHORTENERS.has(parsedDomain.rootDomain)) {
            findings.push({
                id: "URL_SHORTENER_PRESENT",
                title: "Concealed URL Shortener Link",
                explanation: `Uses URL shortener (${host}) that obscures the actual destination.`,
                evidence: host,
                severity: "LOW",
                source: "URL",
                confidence: 75,
                status: "suspicious"
            });
        }

        // 7. Non-standard port
        if (urlStructure.hasPort) {
            findings.push({
                id: "URL_NON_STANDARD_PORT",
                title: "Non-Standard Port Connection",
                explanation: `Connects to non-standard port :${urlStructure.port} instead of standard web ports 80/443.`,
                evidence: `Port ${urlStructure.port}`,
                severity: "MEDIUM",
                source: "URL",
                confidence: 80,
                status: "suspicious"
            });
        }

        // 8. Suspicious redirect params
        if (parsedUrl.search) {
            const queryLower = parsedUrl.search.toLowerCase();
            if (/redirect|return_url|dest|forward|target|login|token|auth/i.test(queryLower)) {
                findings.push({
                    id: "URL_SUSPICIOUS_REDIRECT_PARAM",
                    title: "Suspicious Redirect or Auth Parameter",
                    explanation: "URL contains query parameters frequently exploited for open redirect attacks or credential relay.",
                    evidence: parsedUrl.search.slice(0, 80),
                    severity: "LOW",
                    source: "URL",
                    confidence: 70,
                    status: "suspicious"
                });
            }
        }

        // 9. Unencrypted HTTP
        if (protocol === "http:") {
            findings.push({
                id: "URL_INSECURE_HTTP",
                title: "Unencrypted HTTP Scheme",
                explanation: "URL transmits data unencrypted over plaintext HTTP.",
                evidence: "http://",
                severity: "LOW",
                source: "URL",
                confidence: 85,
                status: "confirmed"
            });
        }

        // 10. DNS Resolution
        const domainInfo = await DomainInformationProvider.inspectDomain(host, protocol);
        if (domainInfo.isInternalOrSsrf) {
            findings.push({
                id: "DNS_REBINDING_INTERNAL_IP",
                title: "DNS Resolves to Internal IP",
                explanation: `Domain '${host}' resolves to private/internal IP ${domainInfo.ip} (DNS rebinding / SSRF vulnerability).`,
                evidence: String(domainInfo.ip),
                severity: "CRITICAL",
                source: "DNS",
                confidence: 100,
                status: "confirmed"
            });
        }

        // 11. Threat Intelligence
        const threatIntel = await ThreatIntelligenceProvider.checkThreatIntelligence(normalizedUrl);
        if (threatIntel.isMalicious) {
            findings.push({
                id: "THREAT_INTEL_CONFIRMED_MALICIOUS",
                title: `Confirmed Malicious by ${threatIntel.provider}`,
                explanation: threatIntel.details,
                evidence: threatIntel.threatType || normalizedUrl,
                severity: "CRITICAL",
                source: "THREAT_INTEL",
                confidence: 100,
                status: "confirmed"
            });
        }

        // Score calculation
        const { verdict, riskScore, category, confidence } = calculateVerdictsAndScores(findings, false);

        let summary = "";
        if (verdict === "High risk") {
            summary = `High risk detected. Identified ${findings.length} threat signal(s) including lookalike domain branding, malicious records, or deceptive subdomains.`;
        } else if (verdict === "Suspicious") {
            summary = `Suspicious URL traits detected. Domain contains anomalies such as high-risk TLDs, shortened links, or non-standard ports requiring caution.`;
        } else if (verdict === "Needs caution") {
            summary = `Guarded link. URL exhibits minor anomalies (such as unencrypted HTTP or query parameters) but no confirmed malicious patterns.`;
        } else {
            summary = `URL structure aligns with standard authentic domain patterns. No active threat signals or lookalike indicators detected.`;
        }

        const recommendedActions = generateRecommendations(verdict, findings);
        const analysisLimitations = [
            "Target page content was not fetched via HTTP to protect user privacy and prevent tracking/exploit delivery.",
            threatIntel.status === "UNAVAILABLE" 
                ? "External threat-intelligence API is not configured. Reputation result reflects local structural rules."
                : `Threat intelligence provided by ${threatIntel.provider}.`
        ];

        return {
            isValid: true,
            url: rawUrl,
            normalizedUrl,
            host,
            rootDomain: parsedDomain.rootDomain,
            verdict,
            riskScore,
            category,
            confidence,
            summary,
            findings,
            urlStructure,
            threatIntelligence: threatIntel,
            domainInfo,
            recommendedActions,
            analysisLimitations,
            scannedAt: new Date().toISOString()
        };
    }
};

// =========================================================================
// 12. MESSAGE ANALYSIS SERVICE (WHATSAPP, INSTAGRAM, TELEGRAM, SMS, ETC.)
// =========================================================================

const MessageAnalysisService = {
    async analyzePastedMessage({ message, source = "OTHER" }) {
        if (!message || typeof message !== "string" || !message.trim()) {
            return {
                isValid: false,
                error: "Message content cannot be empty.",
                verdict: "Likely safe",
                riskScore: 0,
                summary: "Empty message provided.",
                findings: [],
                extractedUrls: [],
                recommendedActions: [],
                analysisLimitations: []
            };
        }

        const rawText = message.trim();
        if (rawText.length > 15000) {
            return {
                isValid: false,
                error: "Message exceeds maximum permitted length of 15,000 characters.",
                verdict: "Needs caution",
                riskScore: 30,
                summary: "Message content was rejected due to excessive length.",
                findings: [{
                    id: "EXCESSIVE_MESSAGE_LENGTH",
                    title: "Message Length Limit Exceeded",
                    explanation: "Submitted text exceeds 15,000 characters limit.",
                    severity: "LOW",
                    source: "SYSTEM",
                    confidence: 100,
                    status: "confirmed"
                }],
                extractedUrls: [],
                recommendedActions: ["Please paste a shorter segment of the suspicious communication."],
                analysisLimitations: ["Analysis aborted for oversized input."]
            };
        }

        const normalizedSource = String(source || "OTHER").toUpperCase();

        // 1. Extract all URLs
        const extractedUrlStrings = extractUrlsFromText(rawText);
        const inspectedUrls = [];
        const urlFindings = [];

        for (const u of extractedUrlStrings) {
            const urlResult = await URLAnalysisService.inspectUrl(u);
            inspectedUrls.push(urlResult);
            if (urlResult && Array.isArray(urlResult.findings)) {
                for (const f of urlResult.findings) {
                    urlFindings.push(f);
                }
            }
        }

        // 2. Content Heuristics & Intent Analysis
        const { findings: contentFindings, isAwarenessOrDiscussion } = analyzeContent(rawText, urlFindings);

        // 3. Social / Messaging Specific Analysis
        const socialFindings = [];
        const textLower = rawText.toLowerCase();

        // A. Telegram task / crypto / work-from-home lure
        if ((normalizedSource === "TELEGRAM" || normalizedSource === "WHATSAPP" || textLower.includes("telegram")) &&
            /subscribe to youtube|like videos|daily profit|crypto investment|part time job|guaranteed returns|vip group/i.test(textLower) &&
            /rs\.?|inr|\$|\d{3,}/i.test(textLower)) {
            socialFindings.push({
                id: "SOCIAL_TELEGRAM_TASK_SCAM",
                title: "Messaging Platform Task / Investment Scam",
                explanation: "Common social-engineering scam promising guaranteed payouts for completing small tasks or joining Telegram VIP groups.",
                evidence: "Task-based earning or investment lure on messaging channel",
                severity: "HIGH",
                source: "CONTENT",
                confidence: 90,
                status: "confirmed"
            });
        }

        // B. WhatsApp Verification Code / Family Emergency Scam
        if ((normalizedSource === "WHATSAPP" || textLower.includes("whatsapp")) &&
            /6-digit code|whatsapp code|sent you a code by mistake|emergency money|i lost my phone/i.test(textLower)) {
            socialFindings.push({
                id: "SOCIAL_WHATSAPP_CODE_THEFT",
                title: "Account Takeover / Stolen Verification Code Scam",
                explanation: "Classic account-hijacking lure asking recipient to forward a 6-digit WhatsApp registration code or claiming a family emergency.",
                evidence: "Request for forwarded verification code or emergency funds",
                severity: "CRITICAL",
                source: "CONTENT",
                confidence: 95,
                status: "confirmed"
            });
        }

        // C. Instagram Sponsorship / Account Copyright Strike Scam
        if ((normalizedSource === "INSTAGRAM" || textLower.includes("instagram")) &&
            /copyright violation|account will be permanently deleted|brand collaboration|ambassador program|fill the form/i.test(textLower)) {
            socialFindings.push({
                id: "SOCIAL_INSTAGRAM_PHISHING_LURE",
                title: "Instagram Copyright / Ambassador Phishing Lure",
                explanation: "Impersonates Instagram copyright enforcement or offers fake brand ambassador sponsorships to harvest social logins.",
                evidence: "Copyright threat or ambassador solicitation",
                severity: "HIGH",
                source: "CONTENT",
                confidence: 90,
                status: "confirmed"
            });
        }

        // D. Extract Contact & Payment Identifiers
        const detectedIdentifiers = [];
        const upiMatches = rawText.match(/[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}/g);
        if (upiMatches) {
            for (const upi of new Set(upiMatches)) {
                if (!upi.endsWith("@gmail.com") && !upi.endsWith("@yahoo.com") && !upi.endsWith("@outlook.com") && !upi.endsWith("@hotmail.com")) {
                    detectedIdentifiers.push({ type: "UPI_ID", value: upi });
                }
            }
        }

        const phoneMatches = rawText.match(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g);
        if (phoneMatches) {
            for (const phone of new Set(phoneMatches)) {
                detectedIdentifiers.push({ type: "PHONE_NUMBER", value: phone.trim() });
            }
        }

        // Combine all findings
        const allFindings = [
            ...urlFindings,
            ...contentFindings,
            ...socialFindings
        ];

        // Deduplicate findings
        const uniqueFindings = [];
        const seenFindingIds = new Set();
        for (const f of allFindings) {
            if (!seenFindingIds.has(f.id)) {
                seenFindingIds.add(f.id);
                uniqueFindings.push(ensureTaxonomy(f));
            }
        }

        const { verdict, riskScore, category, confidence } = calculateVerdictsAndScores(uniqueFindings, isAwarenessOrDiscussion);

        // Grounded Summary
        let summary = "";
        if (verdict === "High risk") {
            const topFindings = uniqueFindings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").map(f => f.title).slice(0, 2).join(" and ");
            summary = `High risk detected. Message exhibits severe threat signals including ${topFindings || "credential theft, fraudulent lures, or suspicious links"}.`;
        } else if (verdict === "Suspicious") {
            summary = `Suspicious traits detected. The message pressures the recipient with urgency, unverified links, or requests for sensitive information.`;
        } else if (verdict === "Needs caution") {
            summary = `Guarded communication. Message contains promotional material or unverified content requiring awareness.`;
        } else {
            summary = `Communication exhibits authentic patterns. No active threat signals, credential harvesting, or deceptive links were detected.`;
        }

        const recommendedActions = generateRecommendations(verdict, uniqueFindings);

        return {
            isValid: true,
            source: normalizedSource,
            verdict,
            riskScore,
            category,
            confidence,
            summary,
            findings: uniqueFindings,
            extractedUrls: inspectedUrls,
            detectedIdentifiers,
            recommendedActions,
            analysisLimitations: [
                "Analyzed as manual untrusted input.",
                "External AI and threat intelligence services did not receive full private metadata."
            ],
            scannedAt: new Date().toISOString()
        };
    }
};

function hasStrongPhishingEvidence(detection) {
    if (!detection) return false;
    if (detection.category === "PHISHING") return true;
    if (detection.verdict === "High risk" || detection.riskScore >= 70) return true;
    if (Array.isArray(detection.findings)) {
        return detection.findings.some(f => 
            f.severity === "CRITICAL" || 
            (f.severity === "HIGH" && (
                (f.id && (
                    f.id.includes("CREDENTIAL") ||
                    f.id.includes("ACCOUNT_THREAT") ||
                    f.id.includes("LOOKALIKE") ||
                    f.id.includes("IMPERSONATION") ||
                    f.id.includes("DECEPTIVE") ||
                    f.id.includes("TRANSACTION_LURE")
                )) ||
                f.evidenceType === "CONTENT_MALICIOUS"
            ))
        );
    }
    return false;
}

module.exports = {
    parseDomain,
    detectLookalikeDomain,
    analyzeUrls,
    analyzeSenderAndAuth,
    analyzeContent,
    analyzeSmsSpecifics,
    calculateVerdictsAndScores,
    extractUrlsFromText,
    analyzeMessage,
    hasStrongPhishingEvidence,
    ThreatIntelligenceProvider,
    DomainInformationProvider,
    RiskScoringService,
    URLAnalysisService,
    MessageAnalysisService
};
