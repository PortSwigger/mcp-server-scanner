package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Optional;

enum FindingKind implements ConsentIssueKind {

    TOKEN_GRANTS_ACCESS(FindingKind.AUTHORIZATION_ISSUE, AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN,
            FindingKind.UNATTENDED + " The code redeemed to an access token that turned an MCP request refused "
                    + "without a token into a success, so anyone who can reach the server can obtain its user's "
                    + "access.",
            FindingKind.AUTHENTICATE, Optional.of(FindingKind.WITHOUT_SESSION)),
    ANONYMOUS_SESSION_AUTHORIZED(FindingKind.AUTHORIZATION_ISSUE, AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.TENTATIVE,
            "The authorization endpoint issued an authorization code to the scanner's newly registered client "
                    + "after the server created a session for an anonymous visitor, with no login form or "
                    + "consent page on the way. A server that deliberately signs every visitor in as a guest "
                    + "behaves this way, so the code may give access only to that guest's account.",
            FindingKind.AUTHENTICATE, Optional.empty()),
    CODE_ISSUED(FindingKind.AUTHORIZATION_ISSUE, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
            FindingKind.UNATTENDED + " The scanner could not show that the code gives access to the MCP server.",
            FindingKind.AUTHENTICATE, Optional.of(FindingKind.WITHOUT_SESSION)),
    ENDPOINT_ALREADY_OPEN(FindingKind.AUTHORIZATION_ISSUE, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM,
            FindingKind.UNATTENDED + " The MCP endpoint already answers without any token, so the token adds no "
                    + "access; anonymous access to the endpoint is reported separately.",
            FindingKind.AUTHENTICATE, Optional.of(FindingKind.WITHOUT_SESSION)),
    CODE_REUSE("MCP OAuth authorization code redeemed more than once", AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.CERTAIN,
            "The token endpoint issued a working access token for an authorization code it had already "
                    + "redeemed. An attacker who intercepts or replays a code obtains tokens alongside the client.",
            "Redeem each authorization code exactly once, atomically, and revoke the tokens already issued for a "
                    + "code presented a second time.",
            Optional.empty());

    private static final String AUTHORIZATION_ISSUE = "MCP OAuth authorization without login or consent";
    private static final String UNATTENDED = "The authorization endpoint issued an authorization code to the "
            + "scanner's newly registered client without asking anyone to log in or consent.";
    private static final String AUTHENTICATE = "Authenticate the user and obtain their consent for the requesting "
            + "client before issuing an authorization code; never approve a request automatically because the "
            + "server has a single user.";
    private static final String WITHOUT_SESSION = "The scanner sent no session cookie or credential of its own, "
            + "and the server set none along the way, so it treats any visitor this way. Burp session handling "
            + "rules that add cookies to extension requests would change this.";

    private final String issueName;
    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence confidence;
    private final String observation;
    private final String remediation;
    private final Optional<String> limits;

    FindingKind(String issueName, AuditIssueSeverity severity, AuditIssueConfidence confidence, String observation,
                String remediation, Optional<String> limits) {
        this.issueName = issueName;
        this.severity = severity;
        this.confidence = confidence;
        this.observation = observation;
        this.remediation = remediation;
        this.limits = limits;
    }

    static FindingKind forAccess(Access access, boolean sessionCreated) {
        if (access == Access.ALREADY_OPEN) {
            return ENDPOINT_ALREADY_OPEN;
        }
        if (sessionCreated) {
            return ANONYMOUS_SESSION_AUTHORIZED;
        }
        return access == Access.GRANTS_ACCESS ? TOKEN_GRANTS_ACCESS : CODE_ISSUED;
    }

    boolean attachesTokenUse() {
        return this == TOKEN_GRANTS_ACCESS || this == ENDPOINT_ALREADY_OPEN;
    }

    @Override
    public String issueName() {
        return issueName;
    }

    @Override
    public AuditIssueSeverity severity() {
        return severity;
    }

    AuditIssueConfidence confidence() {
        return confidence;
    }

    @Override
    public String observation() {
        return observation;
    }

    @Override
    public String remediation() {
        return remediation;
    }

    @Override
    public Optional<String> limits() {
        return limits;
    }
}
