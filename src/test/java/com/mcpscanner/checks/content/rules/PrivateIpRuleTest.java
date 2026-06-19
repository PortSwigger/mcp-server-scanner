package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PrivateIpRuleTest {

    private final PrivateIpRule rule = new PrivateIpRule();

    @Test
    void flagsPrivateRangeUrlAtInformationSeverity() {
        List<Violation> violations = rule.evaluate(field("http://10.0.0.1/"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
    }

    @Test
    void keepsTentativeConfidence() {
        assertThat(rule.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void flags192168Url() {
        assertThat(rule.evaluate(field("http://192.168.1.1/"))).hasSize(1);
    }

    @Test
    void flagsLoopbackUrl() {
        assertThat(rule.evaluate(field("http://127.0.0.1/"))).hasSize(1);
    }

    @Test
    void flagsCloudMetadataUrl() {
        assertThat(rule.evaluate(field("http://169.254.169.254/"))).hasSize(1);
    }

    @Test
    void ignoresPublicIpUrl() {
        assertThat(rule.evaluate(field("http://8.8.8.8/"))).isEmpty();
    }

    @Test
    void ignoresPublicHttpsUrl() {
        assertThat(rule.evaluate(field("https://example.com/"))).isEmpty();
    }

    @Test
    void evaluate_findsPrivateIpInsideSentence() {
        List<Violation> violations = rule.evaluate(field("Backend reachable at http://192.168.1.10/internal."));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("http://192.168.1.10/internal");
    }

    @Test
    void evaluate_findsBareIpv4LiteralInsideText() {
        List<Violation> violations = rule.evaluate(field("Try ssh to 10.0.0.5 for access"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("10.0.0.5");
    }

    @Test
    void evaluate_doesNotFlagPublicIpInsideText() {
        assertThat(rule.evaluate(field("Try 8.8.8.8 DNS"))).isEmpty();
    }

    @Test
    void evaluate_doesNotDoubleFireWhenUrlContainsBareIp() {
        List<Violation> violations = rule.evaluate(field("Connect to http://192.168.1.10/api"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("http://192.168.1.10/api");
    }

    @Test
    void referencesKeepOnlySsrf() {
        assertThat(rule.metadata().references())
                .containsExactly("https://portswigger.net/web-security/ssrf");
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "fetch", "description", value);
    }
}
