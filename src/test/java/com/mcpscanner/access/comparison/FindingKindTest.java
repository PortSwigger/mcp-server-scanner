package com.mcpscanner.access.comparison;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class FindingKindTest {

    @ParameterizedTest
    @EnumSource(AuditIssueConfidence.class)
    void operationAvailableIsHighAtEveryConfidence(AuditIssueConfidence confidence) {
        assertThat(FindingKind.OPERATION_AVAILABLE.severity(confidence)).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @ParameterizedTest
    @EnumSource(value = com.mcpscanner.checks.api.PrincipalRole.class, names = {"PEER", "HIGHER"})
    void operationAvailableToAPeerOrHigherIdentityIsNotCalledLowerPrivilege(
            com.mcpscanner.checks.api.PrincipalRole role) {
        assertThat(FindingKind.OPERATION_AVAILABLE.issueNameFor(role))
                .isEqualTo("MCP operation available to a disallowed identity");
    }

    @ParameterizedTest
    @EnumSource(value = com.mcpscanner.checks.api.PrincipalRole.class, names = {"LOWER", "PRIMARY"})
    void operationAvailableToALowerOrPrimaryIdentityKeepsItsName(com.mcpscanner.checks.api.PrincipalRole role) {
        assertThat(FindingKind.OPERATION_AVAILABLE.issueNameFor(role))
                .isEqualTo("MCP operation available to a lower-privilege identity");
    }

    @ParameterizedTest
    @EnumSource(value = AuditIssueConfidence.class, names = {"CERTAIN", "FIRM"})
    void provenResultIsHigh(AuditIssueConfidence confidence) {
        assertThat(FindingKind.RESULT_AVAILABLE.severity(confidence)).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @ParameterizedTest
    @EnumSource(value = AuditIssueConfidence.class, names = "TENTATIVE")
    void unprovenResultIsMedium(AuditIssueConfidence confidence) {
        assertThat(FindingKind.RESULT_AVAILABLE.severity(confidence)).isEqualTo(AuditIssueSeverity.MEDIUM);
    }
}
