/**
 * Sentinel Security Agent - Email MIME & Security Parser
 * Safely extracts message body, HTML links, and cryptographic authentication headers.
 * Never executes or fetches links or attachments.
 */

function decodeBase64Url(base64UrlStr) {
    if (!base64UrlStr) return "";
    try {
        const base64 = base64UrlStr.replace(/-/g, "+").replace(/_/g, "/");
        return Buffer.from(base64, "base64").toString("utf8");
    } catch (e) {
        return "";
    }
}

function extractHeaders(payloadHeaders = []) {
    const headers = {};
    for (const h of payloadHeaders) {
        const name = (h.name || "").toLowerCase();
        headers[name] = h.value || "";
    }
    return {
        from: headers["from"] || "Unknown Sender",
        to: headers["to"] || "",
        subject: headers["subject"] || "No Subject",
        date: headers["date"] || "",
        replyTo: headers["reply-to"] || "",
        returnPath: headers["return-path"] || "",
        authResults: headers["authentication-results"] || "",
        receivedSpf: headers["received-spf"] || "",
        dkimSignature: headers["dkim-signature"] || ""
    };
}

function parseAuthenticationStatus(authResults, receivedSpf) {
    const authLower = (authResults || "").toLowerCase();
    const spfLower = (receivedSpf || "").toLowerCase();
    const combined = `${authLower} ${spfLower}`;

    let spf = "none";
    let dkim = "none";
    let dmarc = "none";

    // SPF detection: check Authentication-Results and Received-SPF
    if (combined.includes("spf=pass") || spfLower.startsWith("pass") || combined.includes("spf: pass") || combined.includes("pass (google.com")) {
        spf = "pass";
    } else if (combined.includes("spf=fail") || combined.includes("spf=softfail") || combined.includes("spf=permerror") || spfLower.startsWith("fail") || spfLower.startsWith("softfail") || combined.includes("fail (google.com")) {
        spf = "fail";
    }

    // DKIM detection
    if (combined.includes("dkim=pass") || (combined.includes("header.d=") && combined.includes("dkim=pass"))) {
        dkim = "pass";
    } else if (combined.includes("dkim=fail")) {
        dkim = "fail";
    }

    // DMARC detection
    if (combined.includes("dmarc=pass")) {
        dmarc = "pass";
    } else if (combined.includes("dmarc=fail")) {
        dmarc = "fail";
    }

    return { spf, dkim, dmarc };
}

function extractBodyAndUrls(payload) {
    let plainText = "";
    let htmlText = "";
    const urls = [];

    function traverseParts(part) {
        if (!part) return;

        const mimeType = (part.mimeType || "").toLowerCase();
        if (part.body && part.body.data) {
            const decoded = decodeBase64Url(part.body.data);
            if (mimeType === "text/plain") {
                plainText += "\n" + decoded;
            } else if (mimeType === "text/html") {
                htmlText += "\n" + decoded;
            }
        }

        if (Array.isArray(part.parts)) {
            for (const childPart of part.parts) {
                traverseParts(childPart);
            }
        }
    }

    traverseParts(payload);

function isXmlSchemaUrl(urlStr) {
    if (!urlStr) return false;
    const lower = urlStr.toLowerCase();
    return (
        lower.includes("w3.org") ||
        lower.includes("schema.org") ||
        lower.includes("schemas.microsoft.com") ||
        lower.includes("schemas.openxmlformats.org") ||
        lower.includes("xml.org") ||
        lower.includes("purl.org")
    );
}

    // Extract HTML anchor links safely as data
    if (htmlText) {
        const linkRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']*)["'][^>]*>(.*?)<\/a>/gi;
        let match;
        while ((match = linkRegex.exec(htmlText)) !== null) {
            const href = (match[1] || "").trim();
            const rawAnchor = (match[2] || "").replace(/<[^>]+>/g, " ").trim();
            if (href && (href.startsWith("http://") || href.startsWith("https://")) && !isXmlSchemaUrl(href)) {
                urls.push({ href, text: rawAnchor.slice(0, 100) });
            }
        }
    }

    // Extract raw text URLs from plain text body (avoids DOCTYPE and XML schemas)
    const textToScan = plainText || "";
    const urlRegex = /https?:\/\/[^\s<>"'\)]+/gi;
    let urlMatch;
    while ((urlMatch = urlRegex.exec(textToScan)) !== null) {
        const found = urlMatch[0];
        if (!isXmlSchemaUrl(found) && !urls.some(u => u.href === found)) {
            urls.push({ href: found, text: "" });
        }
    }

    // Clean HTML to readable plain text
    const cleanHtml = htmlText
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&quot;/gi, '"');

    const cleanPlain = (plainText || cleanHtml)
        .replace(/\r\n/g, "\n")
        .replace(/[ \t]+/g, " ")
        .replace(/\n\s*\n/g, "\n")
        .trim();

    return {
        bodyText: cleanPlain.slice(0, 5000),
        urls: urls.slice(0, 20)
    };
}

function parseGmailMessage(messageData) {
    if (!messageData || !messageData.payload) {
        return {
            id: messageData?.id || "unknown",
            from: "Unknown",
            subject: "No Subject",
            date: "",
            snippet: messageData?.snippet || "",
            bodyText: messageData?.snippet || "",
            urls: [],
            auth: { spf: "none", dkim: "none", dmarc: "none" }
        };
    }

    const headers = extractHeaders(messageData.payload.headers || []);
    const auth = parseAuthenticationStatus(headers.authResults, headers.receivedSpf);
    const { bodyText, urls } = extractBodyAndUrls(messageData.payload);

    return {
        id: messageData.id,
        from: headers.from,
        to: headers.to,
        subject: headers.subject,
        date: headers.date,
        replyTo: headers.replyTo,
        returnPath: headers.returnPath,
        snippet: messageData.snippet || "",
        bodyText: bodyText || messageData.snippet || "",
        urls,
        auth
    };
}

module.exports = {
    parseGmailMessage
};
