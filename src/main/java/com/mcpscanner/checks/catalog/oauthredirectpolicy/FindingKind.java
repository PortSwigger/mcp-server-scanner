package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

enum FindingKind {
    CODE_DELIVERY(
            "MCP OAuth authorization code sent to unregistered redirect URI",
            AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
            "The authorization endpoint redirected an authorization code to a redirect URI that the scanner's "
                    + "own client never registered. The registered redirect URI of the same client received an "
                    + "OAuth response first, the state matched, and the client's registration listed the "
                    + "registered URI but not the probed one.",
            "This proves that the authorization endpoint does not compare redirect_uri exactly with the client's "
                    + "registered list. It does not prove consent bypass, code redemption or account takeover.",
            "Compare redirect_uri at the authorization endpoint with the client's registered redirect URIs by "
                    + "exact string match (RFC 9700 section 2.1), and reject the request without redirecting "
                    + "when it does not match."),
    ERROR_DELIVERY(
            "MCP OAuth error response sent to unregistered redirect URI",
            AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE,
            "The authorization endpoint redirected an OAuth error response to a redirect URI that the scanner's "
                    + "own client never registered, after the registered redirect URI received an OAuth "
                    + "response with the same state.",
            "An error redirect proves that the endpoint uses an unvalidated redirect_uri, which can act as an "
                    + "open redirect. It does not prove that an authorization code reaches that URI.",
            "Validate redirect_uri against the client's registered redirect URIs before returning any error by "
                    + "redirect. Show unvalidated errors on the authorization server's own page instead."),
    SCRIPT_SCHEME_REGISTRATION(
            "MCP OAuth dynamic client registration accepts script-scheme redirect URI",
            AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE,
            "Anonymous dynamic client registration accepted and echoed a javascript: or data: redirect URI, "
                    + "after an HTTPS redirect URI control registration (not attached) succeeded.",
            "This establishes registration policy only. It does not prove that a consent page navigates to the "
                    + "stored URI, that script runs, or that any user is affected.",
            "Reject javascript:, data: and other script-capable schemes, in any letter case, when clients "
                    + "register redirect URIs (RFC 7591 section 5, RFC 9700 section 4.1.3)."),
    WILDCARD_EXPANSION(
            "MCP OAuth authorization endpoint expands wildcard redirect URI",
            AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM,
            "The scanner's own client registered a wildcard-host redirect URI. The authorization endpoint then "
                    + "redirected an authorization code to a concrete host that only the wildcard matched, after "
                    + "the client's exact registered redirect URI received an OAuth response with the same state, "
                    + "and it explicitly rejected both a host and a path outside the wildcard.",
            "This proves pattern matching of redirect URIs at the authorization endpoint. The scanner chose the "
                    + "wildcard itself, so it shows no theft of another client's code.",
            "Match redirect URIs exactly at the authorization endpoint and refuse wildcard registrations "
                    + "(RFC 9700 section 2.1)."),
    ANY_HOST_REGISTRATION(
            "MCP OAuth dynamic client registration accepts redirect URI on any host",
            AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM,
            "Anonymous dynamic client registration, sent without an initial access token or any other "
                    + "credential, accepted and echoed an HTTPS redirect URI on client.example.com, a third-party "
                    + "host unrelated to the authorization server. Anyone can register a client whose "
                    + "authorization responses go to a host they control, and then send a victim an "
                    + "authorization link for that client.",
            "This establishes registration policy only. The MCP authorization specification allows any HTTPS "
                    + "redirect URI, so this does not prove consent bypass, authorization code delivery or "
                    + "account takeover. The risk depends on whether the authorization server shows a consent "
                    + "page that names the client and its redirect host before it redirects a code.",
            "Restrict the redirect URIs that anonymous clients can register (loopback, client ID metadata "
                    + "documents or an allowlist of hosts), or require an initial access token for dynamic "
                    + "client registration (RFC 7591 section 5). Always show a consent page that names the "
                    + "redirect host for a newly registered client (RFC 9700 sections 4.1 and 4.5).");

    private final String issueName;
    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence confidence;
    private final String observation;
    private final String limits;
    private final String remediation;

    FindingKind(String issueName, AuditIssueSeverity severity, AuditIssueConfidence confidence,
                String observation, String limits, String remediation) {
        this.issueName = issueName;
        this.severity = severity;
        this.confidence = confidence;
        this.observation = observation;
        this.limits = limits;
        this.remediation = remediation;
    }

    String issueName() {
        return issueName;
    }

    AuditIssueSeverity severity() {
        return severity;
    }

    AuditIssueConfidence confidence() {
        return confidence;
    }

    String observation() {
        return observation;
    }

    String limits() {
        return limits;
    }

    String remediation() {
        return remediation;
    }

    static FindingKind forDelivery(Delivery delivery) {
        return delivery == Delivery.CODE ? CODE_DELIVERY : ERROR_DELIVERY;
    }
}
