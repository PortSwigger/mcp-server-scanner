package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.ContentSuppression;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class EmailRule extends RegexContentRule {

    // Local part bounded to the RFC 5321 limit (64) and possessive, with possessive domain labels,
    // so a hostile dot-laden run cannot induce O(n^2) rescanning or deep group-repetition recursion.
    // The label dot carries a `(?=[A-Za-z0-9])` lookahead so a trailing/sentence-final dot is left
    // for the TLD rather than possessively swallowed as a label — i.e. "security@acme.io." matches
    // "security@acme.io". The lookahead is O(1) and there is a single `@`, so find() stays linear.
    private static final Pattern EMAIL = Pattern.compile(
            "[A-Za-z0-9._%+-]{1,64}+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?+\\.(?=[A-Za-z0-9]))++[A-Za-z]{2,}");

    // Reserved, non-routable TLDs (mDNS / common enterprise internal domains): an address here
    // is internal infrastructure noise, not an externally reachable address worth surfacing.
    private static final Set<String> RESERVED_INTERNAL_TLDS = Set.of("local", "internal");

    public EmailRule() {
        super(EMAIL);
    }

    @Override
    public String id() {
        return "discovery-content-scanner.email";
    }

    @Override
    public String displayName() {
        return "Email Addresses";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.INFORMATION;
    }

    @Override
    public AuditIssueConfidence confidence() {
        return AuditIssueConfidence.TENTATIVE;
    }

    @Override
    protected boolean isSuppressedMatch(String match) {
        int atIndex = match.indexOf('@');
        if (atIndex < 0 || atIndex == match.length() - 1) {
            return true;
        }
        String host = match.substring(atIndex + 1);
        return ContentSuppression.isAllowListedHost(host) || hasReservedInternalTld(host);
    }

    private static boolean hasReservedInternalTld(String host) {
        int lastDot = host.lastIndexOf('.');
        if (lastDot < 0) {
            return false;
        }
        return RESERVED_INTERNAL_TLDS.contains(host.substring(lastDot + 1).toLowerCase(Locale.ROOT));
    }

    @Override
    protected boolean appliesDummyTokenSuppression() {
        // Emails are shape-anchored on @host.tld; an address whose domain contains a word like
        // "example" is still a real address, not a documentation placeholder.
        return false;
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.INFO_DISCLOSURE.withReferences(List.of(
                "https://gdpr-info.eu/art-4-gdpr/"));
    }
}
