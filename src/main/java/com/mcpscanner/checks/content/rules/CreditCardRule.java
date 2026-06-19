package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.ContentRule;
import com.mcpscanner.checks.content.ContentSuppression;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.Violation;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CreditCardRule implements ContentRule {

    private static final Pattern CANDIDATE = Pattern.compile("\\b(?:\\d[ -]?){12,18}\\d\\b");
    private static final int MIN_DIGITS = 13;
    private static final int MAX_DIGITS = 19;

    // Publicly documented test PANs (Visa/Mastercard/Amex/Discover/Diners/JCB).
    // They pass Luhn + IIN by design and appear in every payment provider's docs,
    // so a match on one is documentation, not a leaked cardholder number.
    private static final Set<String> KNOWN_TEST_PANS = Set.of(
            "4242424242424242", "4111111111111111", "4012888888881881",
            "5555555555554444", "5105105105105100", "2223003122003222",
            "378282246310005", "371449635398431",
            "6011111111111117", "6011000990139424",
            "30569309025904",
            "3530111333300000",
            // Additional staples documented across payment-provider sandboxes.
            "4000056655665556", "4000002500003155", "4000000000000002",
            "4000000000000069", "5200828282828210");

    @Override
    public String id() {
        return "discovery-content-scanner.credit-card";
    }

    @Override
    public String displayName() {
        return "Credit Card Numbers";
    }

    @Override
    public AuditIssueSeverity severity() {
        // IIN + Luhn is a TENTATIVE match: ~10% of IIN-plausible 16-digit strings pass Luhn,
        // so the ~10% collision space keeps this below the verified credential rules.
        return AuditIssueSeverity.LOW;
    }

    @Override
    public AuditIssueConfidence confidence() {
        // Luhn + IIN is necessary-not-sufficient: ~10% of IIN-plausible 16-digit strings pass Luhn,
        // so a match is a plausible-but-unconfirmed cardholder number.
        return AuditIssueConfidence.TENTATIVE;
    }

    @Override
    public List<Violation> evaluate(InspectedField field) {
        if (field == null || field.value() == null || field.value().isEmpty()) {
            return List.of();
        }
        if (ContentSuppression.isExampleField(field.fieldPath(), field.objectName())) {
            return List.of();
        }
        List<Violation> violations = new ArrayList<>();
        Matcher matcher = CANDIDATE.matcher(field.value());
        while (matcher.find()) {
            String raw = matcher.group();
            String digits = raw.replaceAll("[ -]", "");
            if (digits.length() < MIN_DIGITS || digits.length() > MAX_DIGITS) {
                continue;
            }
            if (!isPlausibleIin(digits)) {
                continue;
            }
            if (KNOWN_TEST_PANS.contains(digits)) {
                continue;
            }
            if (!ContentSuppression.luhn(digits)) {
                continue;
            }
            violations.add(new Violation(this, field, raw));
        }
        return violations;
    }

    private static boolean isPlausibleIin(String digits) {
        if (digits.startsWith("4")) {
            return true;
        }
        if (digits.startsWith("34") || digits.startsWith("37")) {
            return true;
        }
        if (digits.startsWith("6011") || digits.startsWith("65")) {
            return true;
        }
        if (digits.length() >= 2) {
            int two = Integer.parseInt(digits.substring(0, 2));
            if (two >= 51 && two <= 55) {
                return true;
            }
            if (two >= 22 && two <= 27) {
                return true;
            }
            if (two == 62) {
                return true;
            }
            if (two == 36 || two == 38 || two == 39) {
                return true;
            }
        }
        if (digits.length() >= 3) {
            int three = Integer.parseInt(digits.substring(0, 3));
            if (three >= 300 && three <= 305) {
                return true;
            }
            if (three >= 352 && three <= 358) {
                return true;
            }
        }
        return false;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://www.pcisecuritystandards.org/document_library/?category=pcidss"));
    }
}
