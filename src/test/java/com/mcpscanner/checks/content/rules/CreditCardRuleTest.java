package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CreditCardRuleTest {

    private final CreditCardRule rule = new CreditCardRule();

    @Test
    void identifiesVisaNumber() {
        List<Violation> violations = rule.evaluate(field("card 4532015112830366 saved"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("4532015112830366");
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void creditCardRuleIsTentative() {
        // Luhn + IIN is necessary-not-sufficient: ~10% of IIN-plausible 16-digit strings pass Luhn.
        assertThat(rule.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void identifiesMastercardAndAmex() {
        String body = "mc 5500000000000004 amex 340000000000009";

        assertThat(rule.evaluate(field(body))).hasSize(2);
    }

    @Test
    void identifiesNumberWithDashes() {
        List<Violation> violations = rule.evaluate(field("4532-0151-1283-0366"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("4532-0151-1283-0366");
    }

    @Test
    void identifiesNumberWithSpaces() {
        List<Violation> violations = rule.evaluate(field("4532 0151 1283 0366"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("4532 0151 1283 0366");
    }

    @Test
    void ignoresRandom16DigitFailingLuhn() {
        assertThat(rule.evaluate(field("1234567890123456"))).isEmpty();
    }

    @Test
    void doesNotFireOnRandomLuhnValidNumberWithoutIin() {
        // 8888888888888888 is Luhn-valid (16 digits) but starts with 8 — no real PAN starts with 8
        assertThat(rule.evaluate(field("ref 8888888888888888"))).isEmpty();
    }

    @Test
    void firesOnValidVisaPan() {
        assertThat(rule.evaluate(field("4532 0151 1283 0366"))).hasSize(1);
    }

    @Test
    void firesOnValidMastercardPan() {
        assertThat(rule.evaluate(field("5425233430109903"))).hasSize(1);
    }

    @Test
    void firesOnMastercard2SeriesPan() {
        // 2-series Mastercard (2221-2720 BIN range)
        assertThat(rule.evaluate(field("2222420000001113"))).hasSize(1);
    }

    @Test
    void firesOnDiscoverPan() {
        assertThat(rule.evaluate(field("6011000991300009"))).hasSize(1);
    }

    @Test
    void firesOnJcbPan() {
        // 3528-3589 BIN range
        assertThat(rule.evaluate(field("3566002020360505"))).hasSize(1);
    }

    @Test
    void firesOnUnionPayPan() {
        // UnionPay 62xxx — Luhn-valid sample
        assertThat(rule.evaluate(field("6250941006528599"))).hasSize(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "4242424242424242", "4111111111111111", "4012888888881881",
            "5555555555554444", "5105105105105100", "2223003122003222",
            "378282246310005", "371449635398431",
            "6011111111111117", "6011000990139424",
            "30569309025904",
            "3530111333300000",
            // Additional payment-provider sandbox test PANs beyond the original twelve.
            "4000056655665556", "4000002500003155", "4000000000000002",
            "4000000000000069", "5200828282828210"})
    void suppressesDocumentedTestPans(String testPan) {
        assertThat(rule.evaluate(field("Try our sandbox with card " + testPan))).isEmpty();
    }

    @Test
    void suppressesTestPanWithSeparators() {
        assertThat(rule.evaluate(field("4242 4242 4242 4242"))).isEmpty();
        assertThat(rule.evaluate(field("4242-4242-4242-4242"))).isEmpty();
        assertThat(rule.evaluate(field("4000 0566 5566 5556"))).isEmpty();
        assertThat(rule.evaluate(field("5200-8282-8282-8210"))).isEmpty();
    }

    @Test
    void firesOnNonTestLuhnValidPan() {
        // 4532015112830366 is Luhn-valid + Visa IIN but is NOT a documented test PAN.
        List<Violation> violations = rule.evaluate(field("Charged 4532015112830366 just now"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("4532015112830366");
    }

    @Test
    void referencesKeepOnlyPciDss() {
        assertThat(rule.metadata().references()).containsExactly(
                "https://www.pcisecuritystandards.org/document_library/?category=pcidss");
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "payments", "description", value);
    }
}
