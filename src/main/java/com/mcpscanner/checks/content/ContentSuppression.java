package com.mcpscanner.checks.content;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class ContentSuppression {

    private static final Set<String> ALLOW_LISTED_HOSTS = Set.of(
            "example.com", "example.org", "example.net", "test.com", "localhost"
    );
    private static final List<String> DUMMY_TOKENS = List.of(
            "example", "your_api_key", "your_token_here", "placeholder", "replace_me",
            "changeme", "redacted", "<token>", "xxxx", "xxxxxxxx", "***"
    );
    private static final List<String> EXAMPLE_OBJECT_PREFIXES = List.of("example_", "test_", "dummy_");

    private ContentSuppression() {}

    public static boolean isAllowListedHost(String host) {
        if (host == null) {
            return false;
        }
        return ALLOW_LISTED_HOSTS.contains(host.toLowerCase(Locale.ROOT));
    }

    public static boolean isDummyValue(String value) {
        if (value == null) {
            return false;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        for (String token : DUMMY_TOKENS) {
            if (containsWordBoundedToken(lower, token)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsWordBoundedToken(String value, String token) {
        int idx = value.indexOf(token);
        while (idx >= 0) {
            boolean leftBoundary = idx == 0
                    || !Character.isLetterOrDigit(value.charAt(idx - 1));
            int rightIndex = idx + token.length();
            boolean rightBoundary = rightIndex == value.length()
                    || !Character.isLetterOrDigit(value.charAt(rightIndex));
            if (leftBoundary && rightBoundary) {
                return true;
            }
            idx = value.indexOf(token, idx + 1);
        }
        return false;
    }

    public static boolean isExampleField(String fieldPath, String objectName) {
        if (fieldPath != null) {
            if (fieldPath.endsWith(".example") || fieldPath.contains(".examples[")) {
                return true;
            }
        }
        if (objectName == null) {
            return false;
        }
        String lower = objectName.toLowerCase(Locale.ROOT);
        for (String prefix : EXAMPLE_OBJECT_PREFIXES) {
            if (lower.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    public static double shannonEntropy(String value) {
        if (value == null || value.isEmpty()) {
            return 0.0;
        }
        Map<Character, Integer> counts = new HashMap<>();
        for (int i = 0; i < value.length(); i++) {
            counts.merge(value.charAt(i), 1, Integer::sum);
        }
        double length = value.length();
        double entropy = 0.0;
        for (int count : counts.values()) {
            double probability = count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }

    public static boolean luhn(String digits) {
        if (digits == null || digits.isEmpty()) {
            return false;
        }
        int sum = 0;
        boolean alternate = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            char c = digits.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
            int n = c - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) {
                    n -= 9;
                }
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }
}
