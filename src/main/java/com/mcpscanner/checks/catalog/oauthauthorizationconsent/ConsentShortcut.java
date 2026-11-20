package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.SignedInProbe;

import java.util.Arrays;
import java.util.Optional;

enum ConsentShortcut implements ConsentIssueKind {

    ANY_CLIENT(SignedInProbe.FRESH_NAME, "fresh client", "MCP OAuth consent skipped for signed-in user",
            AuditIssueSeverity.HIGH,
            "While the user was signed in, the authorization endpoint issued an authorization code to a newly "
                    + "registered client with an unfamiliar name and a redirect URI on an unrelated host, without "
                    + "showing a consent page. The server trusts the signed-in session alone, so any site that "
                    + "registers a client and sends a signed-in user to its authorization URL receives a code for "
                    + "that user's account.",
            "Obtain the signed-in user's explicit consent before issuing a code to any client they have not "
                    + "approved; a session is authentication, not consent."),
    CLIENT_NAME(SignedInProbe.SAME_NAME, "same client name", "MCP OAuth consent remembered by client name",
            AuditIssueSeverity.HIGH,
            "While the user was signed in, the authorization endpoint issued an authorization code without a "
                    + "consent page to a newly registered client that reused the client_name of the client the "
                    + "user had approved, with a redirect URI on an unrelated host. The server remembers consent by "
                    + "display name, which any registration can copy, so an attacker who registers a client under "
                    + "an approved client's name receives codes for the user's account.",
            FindingRemedies.EXACT_CLIENT),
    REDIRECT_HOST(SignedInProbe.SAME_REDIRECT_HOST, "same redirect host",
            "MCP OAuth consent remembered by redirect host", AuditIssueSeverity.HIGH,
            "While the user was signed in, the authorization endpoint issued an authorization code without a "
                    + "consent page to a newly registered client with a fresh name whose redirect URI is on the "
                    + "approved client's redirect host but on another port and path. The server remembers consent by "
                    + "redirect host, so any client registered with a redirect URI on that host, such as another "
                    + "local application, receives codes for the user's account.",
            FindingRemedies.EXACT_CLIENT),
    CLIENT_ID_PREFIX(SignedInProbe.SAME_CLIENT_ID_PREFIX, "same client_id prefix",
            "MCP OAuth consent remembered by client_id prefix", AuditIssueSeverity.HIGH,
            "While the user was signed in, the authorization endpoint issued an authorization code without a "
                    + "consent page to a newly registered client whose client_id shares the structured prefix of "
                    + "the approved client's client_id, obtained by registering with the approved client's "
                    + "software_id. The server remembers consent by client_id prefix, so anyone who registers with "
                    + "that software_id receives codes for the user's account.",
            FindingRemedies.EXACT_CLIENT),
    BROADER_SCOPE(SignedInProbe.SCOPE_UPGRADE, "scope upgrade", "MCP OAuth consent not re-asked for broader scope",
            AuditIssueSeverity.MEDIUM,
            "While the user was signed in, the authorization endpoint issued an authorization code to the "
                    + "scanner's own approved client for scopes beyond those the user approved, without showing a "
                    + "consent page. The server remembers consent per client regardless of scope, so a client "
                    + "approved for limited access silently obtains broader access.",
            "Store the approved scopes with each remembered consent and show the consent page again whenever a "
                    + "request asks for a scope the user has not approved.");

    private final SignedInProbe probe;
    private final String label;
    private final String issueName;
    private final AuditIssueSeverity severity;
    private final String observation;
    private final String remediation;

    ConsentShortcut(SignedInProbe probe, String label, String issueName, AuditIssueSeverity severity,
                    String observation, String remediation) {
        this.probe = probe;
        this.label = label;
        this.issueName = issueName;
        this.severity = severity;
        this.observation = observation;
        this.remediation = remediation;
    }

    static ConsentShortcut of(SignedInProbe probe) {
        return Arrays.stream(values()).filter(shortcut -> shortcut.probe == probe).findFirst().orElseThrow();
    }

    String label() {
        return label;
    }

    @Override
    public String issueName() {
        return issueName;
    }

    @Override
    public AuditIssueSeverity severity() {
        return severity;
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
        return this == BROADER_SCOPE ? Optional.of(FindingRemedies.UNREDEEMED_CONTROL) : Optional.empty();
    }

    private static final class FindingRemedies {

        static final String UNREDEEMED_CONTROL = "The control code issued at the granted scope was not redeemed "
                + "and may appear in the evidence.";

        static final String EXACT_CLIENT = "Remember an approval only for the exact client_id the user approved, "
                + "with its registered redirect URIs and approved scopes, and show the consent page to every other "
                + "client; never key a remembered approval on client_name, redirect host or a client_id prefix.";
    }
}
