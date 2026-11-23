package com.mcpscanner.access.listing;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

enum ListingIssueKind {
    FAKE_TOKEN_BEYOND_PRIMARY("MCP fake token lists tools the primary user does not list", AuditIssueSeverity.HIGH,
            "The server accepted a bearer token it never issued and answered tools/list with tools that the primary "
                    + "user's real credential does not list. An unrecognised credential is being mapped to a default, "
                    + "fallback or service identity with more privilege than a signed-in user, so anyone can reach "
                    + "those tools by sending any token.",
            "Reject unknown, malformed and invalid credentials with 401 before dispatching any MCP method. Never map "
                    + "an unrecognised token to a default, fallback or service identity.") {
        @Override
        String subject(ListingFinding finding, String exceeded) {
            return PrincipalLabels.describe(finding.synthetic().principal()) + " lists "
                    + finding.extraTools().size() + " tools that the primary user " + exceeded + " does not list: "
                    + String.join(", ", finding.extraTools()) + ".";
        }
    },
    SYNTHETIC_SUPERSET("MCP unauthenticated principal lists more tools than a real user", AuditIssueSeverity.MEDIUM,
            "A caller without a valid credential answered tools/list with every tool a signed-in user lists, plus "
                    + "tools that user does not list. Privilege is inverted: an unauthenticated or unrecognised "
                    + "caller sees more of the server than a real user does.",
            "Authenticate every MCP request before dispatching it, and list and dispatch only the tools the "
                    + "authenticated principal is authorised to use. A caller without a valid credential must never "
                    + "see more than a signed-in user.") {
        @Override
        String subject(ListingFinding finding, String exceeded) {
            return PrincipalLabels.describe(finding.synthetic().principal()) + " lists every tool that "
                    + exceeded + " list, plus tools none of them list: " + String.join(", ", finding.extraTools())
                    + ".";
        }
    };

    private final String issueName;
    private final AuditIssueSeverity unconfirmedSeverity;
    private final String background;
    private final String remediation;

    ListingIssueKind(String issueName, AuditIssueSeverity unconfirmedSeverity, String background,
                     String remediation) {
        this.issueName = issueName;
        this.unconfirmedSeverity = unconfirmedSeverity;
        this.background = background;
        this.remediation = remediation;
    }

    abstract String subject(ListingFinding finding, String exceeded);

    String issueName() {
        return issueName;
    }

    String background() {
        return background;
    }

    String remediation() {
        return remediation;
    }

    AuditIssueSeverity severity(boolean confirmed) {
        return confirmed ? AuditIssueSeverity.HIGH : unconfirmedSeverity;
    }

    AuditIssueConfidence confidence(boolean confirmed) {
        return confirmed ? AuditIssueConfidence.CERTAIN : AuditIssueConfidence.FIRM;
    }
}
