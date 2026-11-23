package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Optional;

final class UncontrolledShortcut implements ConsentIssueKind {

    static final UncontrolledShortcut INSTANCE = new UncontrolledShortcut();

    private UncontrolledShortcut() {
    }

    @Override
    public String issueName() {
        return ConsentShortcut.ANY_CLIENT.issueName();
    }

    @Override
    public AuditIssueSeverity severity() {
        return ConsentShortcut.ANY_CLIENT.severity();
    }

    @Override
    public String observation() {
        return "While the user was signed in, the authorization endpoint issued an authorization code without a "
                + "consent page to a newly registered client that reused the client_name of the client the user had "
                + "approved, with a redirect URI on an unrelated host. The fresh-name control that would tell "
                + "whether the server skips consent for any client or remembers it by display name gave no clear "
                + "answer, so either applies: any site that registers a client, under any name or under an "
                + "approved client's name, and sends a signed-in user to its authorization URL may receive a code "
                + "for that user's account.";
    }

    @Override
    public String remediation() {
        return ConsentShortcut.CLIENT_NAME.remediation();
    }

    @Override
    public Optional<String> limits() {
        return Optional.empty();
    }
}
