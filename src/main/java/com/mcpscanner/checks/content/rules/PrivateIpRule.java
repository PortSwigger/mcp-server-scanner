package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.oauth.OAuthUrlValidator;
import com.mcpscanner.checks.content.ContentRule;
import com.mcpscanner.checks.content.ContentSuppression;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.Violation;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PrivateIpRule implements ContentRule {

    private static final Set<String> FLAGGED_CLASSIFICATIONS = Set.of(
            OAuthUrlValidator.CLASSIFICATION_LOOPBACK,
            OAuthUrlValidator.CLASSIFICATION_PRIVATE,
            OAuthUrlValidator.CLASSIFICATION_LINK_LOCAL,
            OAuthUrlValidator.CLASSIFICATION_CLOUD_METADATA
    );
    private static final Pattern URL_PATTERN = Pattern.compile("\\bhttps?://[^\\s)>\"'<]+");
    private static final Pattern BARE_IPV4_PATTERN = Pattern.compile("\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b");

    private final OAuthUrlValidator urlValidator = new OAuthUrlValidator();

    @Override
    public String id() {
        return "discovery-content-scanner.private-ip";
    }

    @Override
    public String displayName() {
        return "Private/Loopback URLs";
    }

    @Override
    public AuditIssueSeverity severity() {
        // Local-dev/loopback URLs in setup docs are ubiquitous and usually intentional,
        // so this is informational context rather than a defect on its own.
        return AuditIssueSeverity.INFORMATION;
    }

    @Override
    public AuditIssueConfidence confidence() {
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
        List<int[]> urlSpans = collectUrlMatches(field, violations);
        collectBareIpv4Matches(field, urlSpans, violations);
        return violations;
    }

    private List<int[]> collectUrlMatches(InspectedField field, List<Violation> sink) {
        List<int[]> spans = new ArrayList<>();
        Matcher matcher = URL_PATTERN.matcher(field.value());
        while (matcher.find()) {
            spans.add(new int[]{matcher.start(), matcher.end()});
            String candidate = stripTrailingPunctuation(matcher.group());
            classifyAsUri(candidate).ifPresent(c -> sink.add(new Violation(this, field, candidate)));
        }
        return spans;
    }

    private void collectBareIpv4Matches(InspectedField field, List<int[]> urlSpans, List<Violation> sink) {
        Matcher matcher = BARE_IPV4_PATTERN.matcher(field.value());
        while (matcher.find()) {
            if (isInsideAnySpan(matcher.start(), urlSpans)) {
                continue;
            }
            String literal = matcher.group();
            classifyAsBareHost(literal).ifPresent(c -> sink.add(new Violation(this, field, literal)));
        }
    }

    private static boolean isInsideAnySpan(int position, List<int[]> spans) {
        for (int[] span : spans) {
            if (position >= span[0] && position < span[1]) {
                return true;
            }
        }
        return false;
    }

    private Optional<String> classifyAsUri(String candidate) {
        try {
            URI uri = URI.create(candidate);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return Optional.empty();
            }
            return flaggedClassification(uri);
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    private Optional<String> classifyAsBareHost(String literal) {
        try {
            URI uri = URI.create("http://" + literal);
            if (uri.getHost() == null) {
                return Optional.empty();
            }
            return flaggedClassification(uri);
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    private Optional<String> flaggedClassification(URI uri) {
        Optional<String> classification = urlValidator.classify(uri);
        if (classification.isEmpty() || !FLAGGED_CLASSIFICATIONS.contains(classification.get())) {
            return Optional.empty();
        }
        return classification;
    }

    private static String stripTrailingPunctuation(String value) {
        int end = value.length();
        while (end > 0 && isTrailingPunctuation(value.charAt(end - 1))) {
            end--;
        }
        return value.substring(0, end);
    }

    private static boolean isTrailingPunctuation(char c) {
        return c == '.' || c == ',' || c == ';' || c == ':' || c == ')' || c == ']' || c == '!' || c == '?';
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.INFO_DISCLOSURE.withReferences(List.of(
                "https://portswigger.net/web-security/ssrf"));
    }
}
