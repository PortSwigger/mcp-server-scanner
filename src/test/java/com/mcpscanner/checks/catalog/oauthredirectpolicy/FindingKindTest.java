package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class FindingKindTest {

    @Test
    void codeDeliveryMapsToCodeDeliveryFinding() {
        assertThat(FindingKind.forDelivery(Delivery.CODE)).isEqualTo(FindingKind.CODE_DELIVERY);
    }

    @Test
    void errorDeliveryMapsToErrorDeliveryFinding() {
        assertThat(FindingKind.forDelivery(Delivery.ERROR)).isEqualTo(FindingKind.ERROR_DELIVERY);
    }

    @Test
    void onlyCodeDeliveryIsRatedAboveInformation() {
        assertThat(FindingKind.CODE_DELIVERY.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(FindingKind.CODE_DELIVERY.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(FindingKind.ERROR_DELIVERY.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(FindingKind.SCRIPT_SCHEME_REGISTRATION.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(FindingKind.WILDCARD_EXPANSION.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(FindingKind.ANY_HOST_REGISTRATION.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
    }

    @Test
    void anyHostRegistrationIsFirmAndSaysWhatItDoesNotProve() {
        assertThat(FindingKind.ANY_HOST_REGISTRATION.issueName())
                .isEqualTo("MCP OAuth dynamic client registration accepts redirect URI on any host");
        assertThat(FindingKind.ANY_HOST_REGISTRATION.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(FindingKind.ANY_HOST_REGISTRATION.limits())
                .contains("registration policy only", "consent bypass", "account takeover", "consent page");
        assertThat(FindingKind.ANY_HOST_REGISTRATION.remediation())
                .contains("initial access token", "RFC 7591 section 5", "RFC 9700");
    }
}
