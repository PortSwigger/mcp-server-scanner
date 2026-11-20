package com.mcpscanner.checks.catalog.oauthrefreshgrant;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.grant.ClientType;
import com.mcpscanner.checks.issue.IssueBodyBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

final class OAuthRefreshGrantIssues {

    static final String CLIENT_AUTHENTICATION_ISSUE = "OAuth refresh grant accepted without confidential client authentication";
    static final String SCOPE_EXPANSION_ISSUE = "OAuth refresh grant expanded the granted scope";

    private static final String CLIENT_AUTHENTICATION_REMEDIATION =
            "Authenticate the confidential client on every refresh_token grant (RFC 6749 section 6) and reject the "
                    + "request with invalid_client when the client secret is missing or wrong.";
    private static final String SCOPE_EXPANSION_REMEDIATION =
            "Reject a refresh_token grant whose scope parameter includes any scope not originally granted by the "
                    + "resource owner (RFC 6749 section 6) with invalid_scope, and issue at most the original scope.";

    private static final String TOOLS_LIST_ATTACHMENT =
            "the MCP tools/list request sent with the access token it issued";

    private final String baseUrl;

    OAuthRefreshGrantIssues(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    AuditIssue clientAuthentication(ClientAuthenticationFinding finding) {
        JudgedRefresh attached = finding.strongestAccepted();
        List<String> items = new ArrayList<>();
        items.add("Client type: " + describe(finding.clientType(), finding.confidentialityEstablished()));
        items.add(control(finding.evidence()));
        finding.accepted().forEach(refresh -> items.add("Refreshing with " + refresh.exchange().authentication().description()
                + " returned HTTP " + refresh.exchange().status() + " with a new access token; "
                + usability(refresh.usability())));
        String detail = new IssueBodyBuilder()
                .paragraph("The authorization server issued tokens on a refresh_token grant for a confidential client "
                        + "without verifying the client's secret. Anyone holding a leaked refresh token can redeem it "
                        + "without the client credentials that should bind it to the client.")
                .findings(items)
                .paragraph("Attached: the refresh with " + attached.exchange().authentication().description()
                        + ", " + TOOLS_LIST_ATTACHMENT + ", and the refused refresh with the unissued refresh token.")
                .build();
        return issue(CLIENT_AUTHENTICATION_ISSUE, detail, CLIENT_AUTHENTICATION_REMEDIATION, finding.confidence(),
                attached(Stream.concat(exchanges(attached), unissuedControl(finding.evidence()))));
    }

    AuditIssue scopeExpansion(ScopeExpansionFinding finding) {
        ScopeProbe probe = finding.probe();
        String original = String.join(" ", probe.original().scopes().stream().sorted().toList());
        List<String> items = List.of(
                "Original scope: \"" + original + "\" ("
                        + (probe.original().declaredByAuthorizationServer()
                        ? "declared by the authorization server on a plain refresh"
                        : "the scope the extension requested; the server did not declare it") + ")",
                "Requested on refresh: the original scope plus \"" + probe.extraScope() + "\"",
                "The server answered HTTP " + probe.refresh().exchange().status() + " and declared a granted scope that includes \""
                        + probe.extraScope() + "\"; " + usability(probe.refresh().usability()),
                control(finding.evidence()));
        String detail = new IssueBodyBuilder()
                .paragraph(probe.original().declaredByAuthorizationServer()
                        ? "The authorization server granted a scope on a refresh_token grant that the original grant "
                        + "did not include. A refresh token can therefore be used to escalate the privileges the "
                        + "resource owner consented to."
                        : "The authorization server granted a scope on a refresh_token grant that the extension did "
                        + "not request when it was authorized. The server never declared the original grant's scope, "
                        + "so it may have added this scope by default from the start; if it did not, a refresh "
                        + "token can be used to escalate the privileges the resource owner consented to.")
                .findings(items)
                .paragraph("Attached: " + (probe.original().declaredByAuthorizationServer()
                        ? "the plain refresh that declared the original scope, " : "")
                        + "the refresh that requested the extra scope, and " + TOOLS_LIST_ATTACHMENT + ".")
                .paragraph("The check did not exercise an operation that requires the extra scope, so the practical "
                        + "effect depends on how the MCP server enforces it. " + (probe.restored()
                        ? "The live session was narrowed back to its original scope after the probe."
                        : "Narrowing the live session back to its original scope failed, so the extension may keep "
                        + "using the expanded token until it next refreshes."))
                .build();
        return issue(SCOPE_EXPANSION_ISSUE, detail, SCOPE_EXPANSION_REMEDIATION, finding.confidence(),
                attached(Stream.concat(originalScopeSource(probe, finding.evidence()), exchanges(probe.refresh()))));
    }

    private AuditIssue issue(String name, String detail, String remediation, AuditIssueConfidence confidence,
                             List<HttpRequestResponse> evidence) {
        return AuditIssue.auditIssue(name, detail, remediation, baseUrl, AuditIssueSeverity.MEDIUM, confidence,
                OAuthRefreshGrantDescriptor.DESCRIPTOR.issueBackground(), remediation, AuditIssueSeverity.MEDIUM,
                evidence);
    }

    private static Stream<HttpRequestResponse> exchanges(JudgedRefresh refresh) {
        return Stream.concat(Stream.of(refresh.exchange().exchange()), refresh.token().map(JudgedToken::candidate).stream());
    }

    private static Stream<HttpRequestResponse> unissuedControl(RefreshEvidence evidence) {
        return evidence.unissuedControl().map(RefreshExchange::exchange).stream();
    }

    private static Stream<HttpRequestResponse> originalScopeSource(ScopeProbe probe, RefreshEvidence evidence) {
        return probe.original().declaredByAuthorizationServer()
                ? Stream.of(evidence.control().exchange())
                : Stream.empty();
    }

    private static List<HttpRequestResponse> attached(Stream<HttpRequestResponse> evidence) {
        return evidence.filter(Objects::nonNull).toList();
    }

    private static String control(RefreshEvidence evidence) {
        return "Controls: a refresh with the registered client credentials returned HTTP " + evidence.control().status()
                + " with a new access token (attached only when it declared the original scope), and an unissued "
                + "refresh token was refused with HTTP "
                + evidence.unissuedControl().map(RefreshExchange::status).orElse(0);
    }

    private static String usability(Usability usability) {
        return switch (usability) {
            case USABLE -> "the issued access token listed the MCP server's tools exactly as the live session does, "
                    + "while requests without a token and with a malformed token were refused";
            case UNVERIFIED -> "whether the issued access token works on the MCP endpoint could not be verified";
            case NOT_USABLE -> "the issued access token was refused by the MCP endpoint";
        };
    }

    private static String describe(ClientType type, boolean established) {
        if (type == ClientType.CONFIDENTIAL_REGISTERED) {
            return "confidential (dynamic client registration returned a client secret with a client-secret "
                    + "token_endpoint_auth_method)";
        }
        return established
                ? "confidential (client secret configured in the extension; the server supports only confidential "
                + "clients)"
                : "assumed confidential because a client secret is configured in the extension; the server also "
                + "supports public clients, so the check could not confirm that this client is confidential";
    }
}
