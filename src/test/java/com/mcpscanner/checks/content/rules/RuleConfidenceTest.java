package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.checks.content.ContentRule;
import com.mcpscanner.checks.content.ContentRules;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RuleConfidenceTest {

    private static final Set<String> TENTATIVE_RULE_IDS = Set.of(
            "discovery-content-scanner.email",
            "discovery-content-scanner.private-ip",
            "discovery-content-scanner.jwt",
            "discovery-content-scanner.credit-card");

    @Test
    void emailRuleIsTentative() {
        assertThat(new EmailRule().confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void privateIpRuleIsTentative() {
        assertThat(new PrivateIpRule().confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void jwtRuleIsTentative() {
        assertThat(new JwtRule().confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void creditCardRuleIsTentative() {
        assertThat(new CreditCardRule().confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void allOtherDefaultRulesAreFirm() {
        for (ContentRule rule : ContentRules.all()) {
            if (TENTATIVE_RULE_IDS.contains(rule.id())) {
                continue;
            }
            assertThat(rule.confidence())
                    .as("rule %s should default to FIRM", rule.id())
                    .isEqualTo(AuditIssueConfidence.FIRM);
        }
    }
}
