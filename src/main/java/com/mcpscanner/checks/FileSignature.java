package com.mcpscanner.checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public enum FileSignature {
    PASSWD("Unix password file") {
        @Override
        public boolean matches(String text) {
            return matchesAnyView(text, FileSignature::matchesPasswd);
        }
    },
    HOSTS("hosts file") {
        @Override
        public boolean matches(String text) {
            return matchesAnyView(text, FileSignature::matchesHosts);
        }
    },
    WIN_INI("Windows win.ini") {
        @Override
        public boolean matches(String text) {
            // No newline anchoring: the markers are substrings, so a JSON-escaped view cannot
            // change the result. The shared helper is still applied for uniformity.
            return matchesAnyView(text, FileSignature::matchesWinIni);
        }
    };

    private final String humanLabel;

    FileSignature(String humanLabel) {
        this.humanLabel = humanLabel;
    }

    public String humanLabel() {
        return humanLabel;
    }

    public abstract boolean matches(String text);

    /**
     * Runs the (strict, line-anchored) signature against the raw text first; failing that, against a
     * JSON-decoded view. A server that returns leaked file bytes inside a JSON string envelope
     * ({@code "content":"root:x:0:0:...\\ndaemon:..."}) keeps the file's own newlines as literal
     * {@code \n} escape sequences, which defeats the {@code (?m)^} anchors.
     *
     * <p>The JSON-decoded view is JSON-AWARE: each STRING LEAF VALUE is tested independently, so a
     * coherent file body carried in ONE value matches at its real (Jackson-decoded) line starts,
     * while distinct benign fields are tested in isolation and can never combine across fields to
     * manufacture a match. If the text is not valid JSON, a single whole-text literal-{@code \n}
     * unescape is the only fallback — it is applied to the entire string as one value, so it cannot
     * fabricate cross-field line starts either.
     */
    private static boolean matchesAnyView(String text, Predicate<String> signature) {
        if (signature.test(text)) {
            return true;
        }
        for (String leaf : decodedStringLeaves(text)) {
            if (signature.test(leaf)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Best-effort decode of {@code text} into the individual string values a signature should be
     * tested against. When {@code text} parses as JSON, every string leaf (walking nested
     * objects/arrays) is returned with Jackson's escape decoding already applied, so {@code \n} /
     * {@code \r} / nested escapes become real newlines for that one value. A double-escaped
     * envelope (Jackson decodes {@code \\n} to a literal two-char {@code \n}) still carries literal
     * escapes after one decode, so each leaf that still differs under a literal-{@code \n} unescape
     * contributes that second view too. When the text is not JSON, a single whole-text
     * literal-{@code \n} unescape is the only fallback. Each view is per-VALUE, so distinct benign
     * fields can never combine across fields to manufacture a match.
     */
    private static List<String> decodedStringLeaves(String text) {
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(text);
            if (root != null && !root.isMissingNode()) {
                List<String> views = new ArrayList<>();
                collectStringLeaves(root, views);
                return views;
            }
        } catch (Exception notJson) {
            // fall through to the literal-escape fallback below
        }
        return literalUnescapedView(text);
    }

    private static void collectStringLeaves(JsonNode node, List<String> views) {
        if (node.isTextual()) {
            String value = node.asText();
            views.add(value);
            views.addAll(literalUnescapedView(value));
        } else if (node.isContainerNode()) {
            for (JsonNode child : node) {
                collectStringLeaves(child, views);
            }
        }
    }

    private static List<String> literalUnescapedView(String value) {
        String unescaped = unescapeLiteralLineBreaks(value);
        return unescaped.equals(value) ? List.of() : List.of(unescaped);
    }

    private static String unescapeLiteralLineBreaks(String text) {
        return text.replace("\\\\n", "\n")
                .replace("\\n", "\n")
                .replace("\\r", "\r");
    }

    private static boolean matchesPasswd(String text) {
        if (!PASSWD_ROOT_LINE.matcher(text).find()) {
            return false;
        }
        // Corroboration requires >=2 DISTINCT non-root user entries. PASSWD_USER_LINE also matches
        // the root line, so the root line is excluded; usernames are de-duplicated into a Set so a
        // body that merely repeats the SAME non-root line twice cannot satisfy the bar.
        Matcher userMatcher = PASSWD_USER_LINE.matcher(text);
        Set<String> distinctNonRootUsers = new HashSet<>();
        while (userMatcher.find()) {
            if (PASSWD_ROOT_LINE.matcher(userMatcher.group()).find()) {
                continue;
            }
            distinctNonRootUsers.add(userMatcher.group(1));
            if (distinctNonRootUsers.size() >= 2) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesHosts(String text) {
        return HOSTS_LOCALHOST_LINE.matcher(text).find()
                && HOSTS_CORROBORATING_LINE.matcher(text).find();
    }

    private static boolean matchesWinIni(String text) {
        String lower = text.toLowerCase();
        return lower.contains(WIN_INI_FONTS_MARKER) || lower.contains(WIN_INI_16BIT_MARKER);
    }

    private static final Pattern PASSWD_ROOT_LINE = Pattern.compile("(?m)^root:[^:]*:0:0:");
    private static final Pattern PASSWD_USER_LINE =
            Pattern.compile("(?m)^([a-z_][a-z0-9_-]{0,31}):[^\\n]*:[0-9]+:[0-9]+:");
    private static final Pattern HOSTS_LOCALHOST_LINE = Pattern.compile("(?m)^127\\.0\\.0\\.1\\s+localhost");
    private static final Pattern HOSTS_CORROBORATING_LINE =
            Pattern.compile("(?m)^(::1|255\\.255\\.255\\.255|fe00::0|ff00::0|ff02::[12])\\s");
    private static final String WIN_INI_FONTS_MARKER = "[fonts]";
    private static final String WIN_INI_16BIT_MARKER = "; for 16-bit app support";
}
