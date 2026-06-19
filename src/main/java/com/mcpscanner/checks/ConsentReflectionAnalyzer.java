package com.mcpscanner.checks;

import java.util.Locale;

/**
 * Pure analyzer for the OAuth consent-page reflected-XSS precondition. Decides, from a consent
 * HTML document plus its {@code Content-Security-Policy} header, whether an attacker-controlled
 * DCR {@code client_name} canary survived un-encoded in a tag-parsing (executable) context, and
 * whether a CSP would neutralize execution.
 *
 * <p>Deliberately decoupled from Burp/HTTP so the string/HTML/CSP reasoning is unit-testable in
 * isolation. The canary {@code marker} is the literal breakout tag the check planted (e.g.
 * {@code <mcpxss-canary-abc123>}); RAW survival of that literal tag is the structural-breakout
 * signal.
 */
public final class ConsentReflectionAnalyzer {

    public enum ReflectionContext {
        RAW_SCRIPT_ISLAND,
        RAW_BODY_OR_ATTRIBUTE,
        HTML_COMMENT,
        ENTITY_ENCODED,
        STRIPPED,
        ABSENT
    }

    public record Verdict(ReflectionContext context, boolean cspMitigates) {
        public boolean isRawBreakout() {
            return context == ReflectionContext.RAW_SCRIPT_ISLAND
                    || context == ReflectionContext.RAW_BODY_OR_ATTRIBUTE;
        }
    }

    public Verdict analyze(String html, String cspHeaderValue, String marker) {
        ReflectionContext context = classifyReflection(html, marker);
        boolean cspMitigates = cspMitigatesInlineScript(cspHeaderValue);
        return new Verdict(context, cspMitigates);
    }

    private static ReflectionContext classifyReflection(String html, String marker) {
        if (html == null || html.isEmpty()) {
            return ReflectionContext.ABSENT;
        }
        int rawIndex = html.indexOf(marker);
        if (rawIndex >= 0) {
            if (isInsideScriptIsland(html, rawIndex)) {
                return ReflectionContext.RAW_SCRIPT_ISLAND;
            }
            if (isInsideHtmlComment(html, rawIndex)) {
                return ReflectionContext.HTML_COMMENT;
            }
            return ReflectionContext.RAW_BODY_OR_ATTRIBUTE;
        }
        if (html.contains(entityEncode(marker))) {
            return ReflectionContext.ENTITY_ENCODED;
        }
        if (html.contains(stripTagBrackets(marker))) {
            return ReflectionContext.STRIPPED;
        }
        return ReflectionContext.ABSENT;
    }

    private static boolean isInsideScriptIsland(String html, int index) {
        int lastOpen = html.lastIndexOf("<script", index);
        if (lastOpen < 0) {
            return false;
        }
        int closeOfOpenTag = html.indexOf('>', lastOpen);
        if (closeOfOpenTag < 0 || closeOfOpenTag > index) {
            return false;
        }
        int closeIsland = html.indexOf("</script", closeOfOpenTag);
        return closeIsland < 0 || closeIsland > index;
    }

    /**
     * True when the marker at {@code index} survives only inside an unterminated HTML comment — the
     * nearest preceding {@code <!--} is not closed by a {@code -->} before the marker. A marker the
     * browser keeps inside a comment is never parsed as a tag, so it is not executable. A canary that
     * carries the comment-close sequence lands after the comment ends and is NOT treated as commented.
     */
    private static boolean isInsideHtmlComment(String html, int index) {
        int lastOpen = html.lastIndexOf("<!--", index);
        if (lastOpen < 0) {
            return false;
        }
        int closeComment = html.indexOf("-->", lastOpen);
        return closeComment < 0 || closeComment > index;
    }

    private static String entityEncode(String marker) {
        return marker.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String stripTagBrackets(String marker) {
        return marker.replace("<", "").replace(">", "");
    }

    private static boolean cspMitigatesInlineScript(String cspHeaderValue) {
        if (cspHeaderValue == null || cspHeaderValue.isBlank()) {
            return false;
        }
        String effectiveScriptSrc = effectiveScriptSrc(cspHeaderValue);
        if (effectiveScriptSrc == null) {
            return false;
        }
        if (effectiveScriptSrc.contains("'unsafe-inline'")) {
            return false;
        }
        return !isScriptWildcard(effectiveScriptSrc);
    }

    private static String effectiveScriptSrc(String cspHeaderValue) {
        String scriptSrc = directiveValue(cspHeaderValue, "script-src");
        if (scriptSrc != null) {
            return scriptSrc;
        }
        return directiveValue(cspHeaderValue, "default-src");
    }

    private static String directiveValue(String cspHeaderValue, String directive) {
        for (String segment : cspHeaderValue.split(";")) {
            String trimmed = segment.trim();
            String lowered = trimmed.toLowerCase(Locale.ROOT);
            if (lowered.equals(directive) || lowered.startsWith(directive + " ")) {
                return trimmed.substring(directive.length()).trim().toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }

    private static boolean isScriptWildcard(String scriptSrc) {
        for (String source : scriptSrc.split("\\s+")) {
            if (source.equals("*") || source.equals("http:") || source.equals("https:")) {
                return true;
            }
        }
        return false;
    }
}
