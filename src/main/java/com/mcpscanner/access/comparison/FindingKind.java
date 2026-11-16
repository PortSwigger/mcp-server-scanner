package com.mcpscanner.access.comparison;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.crossidentity.ResultAvailable;

enum FindingKind {
    OPERATION_AVAILABLE("MCP operation available to a lower-privilege identity",
            "An MCP operation that the configured access expectation reserves for other identities returned the "
                    + "owner's exact result to a lower-privilege or otherwise disallowed identity, while an "
                    + "anonymous request was refused.") {
        @Override
        String issueNameFor(PrincipalRole identityRole) {
            return identityRole == PrincipalRole.PEER || identityRole == PrincipalRole.HIGHER
                    ? "MCP operation available to a disallowed identity" : issueName();
        }

        @Override
        AuditIssueSeverity severity(AuditIssueConfidence confidence) {
            return AuditIssueSeverity.HIGH;
        }

        @Override
        String strength(AuditIssueConfidence confidence) {
            return "";
        }
    },
    RESULT_AVAILABLE(ResultAvailable.ISSUE_NAME, ResultAvailable.BACKGROUND) {
        @Override
        AuditIssueSeverity severity(AuditIssueConfidence confidence) {
            return ResultAvailable.severity(confidence);
        }

        @Override
        String strength(AuditIssueConfidence confidence) {
            return ResultAvailable.strength(confidence);
        }
    };

    private final String issueName;
    private final String background;

    FindingKind(String issueName, String background) {
        this.issueName = issueName;
        this.background = background;
    }

    abstract AuditIssueSeverity severity(AuditIssueConfidence confidence);

    abstract String strength(AuditIssueConfidence confidence);

    String issueName() {
        return issueName;
    }

    String issueNameFor(PrincipalRole identityRole) {
        return issueName;
    }

    String background() {
        return background;
    }
}
