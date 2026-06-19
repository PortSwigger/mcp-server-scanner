package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;
import java.util.regex.Pattern;

public final class StripeKeyRule extends HighEntropyCredentialRule {

    private static final Pattern STRIPE = Pattern.compile("[sr]k_(?:live|test)_[A-Za-z0-9]{24,}");
    private static final Pattern STRIPE_WEBHOOK = Pattern.compile("whsec_[A-Za-z0-9]{32,}");

    public StripeKeyRule() {
        super(STRIPE, STRIPE_WEBHOOK);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.stripe-key";
    }

    @Override
    public String displayName() {
        return "Stripe Keys";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.HIGH;
    }

    @Override
    protected AuditIssueSeverity severityFor(String match) {
        // sk_test_/rk_test_ are sandbox credentials with no production blast radius — still worth
        // surfacing, but at LOW so they do not crowd out genuine live-secret (sk_live_) findings.
        return match.startsWith("sk_test_") || match.startsWith("rk_test_")
                ? AuditIssueSeverity.LOW
                : AuditIssueSeverity.HIGH;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://docs.stripe.com/keys",
                "https://docs.stripe.com/keys/restricted-api-keys"));
    }
}
