package com.mcpscanner.checks;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ConsentReflectionAnalyzerTest {

    private static final String MARKER = "<mcpxss-canary-abc123>";

    private final ConsentReflectionAnalyzer analyzer = new ConsentReflectionAnalyzer();

    @Test
    void rawMarkerInsideScriptIslandIsScriptContext() {
        String html = "<html><head><script>var meta = {\"client_name\": \"x"
                + MARKER + "\"};</script></head><body></body></html>";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, null, MARKER);

        assertThat(verdict.context()).isEqualTo(ConsentReflectionAnalyzer.ReflectionContext.RAW_SCRIPT_ISLAND);
        assertThat(verdict.cspMitigates()).isFalse();
    }

    @Test
    void rawMarkerInBodyIsBodyOrAttributeContext() {
        String html = "<html><body><h1>Authorize " + MARKER + "</h1></body></html>";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, null, MARKER);

        assertThat(verdict.context()).isEqualTo(ConsentReflectionAnalyzer.ReflectionContext.RAW_BODY_OR_ATTRIBUTE);
    }

    @Test
    void rawMarkerInAttributeIsBodyOrAttributeContext() {
        String html = "<html><body><div title=\"" + MARKER + "\">consent</div></body></html>";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, null, MARKER);

        assertThat(verdict.context()).isEqualTo(ConsentReflectionAnalyzer.ReflectionContext.RAW_BODY_OR_ATTRIBUTE);
    }

    @Test
    void entityEncodedMarkerIsEntityEncodedContext() {
        String html = "<html><body><h1>Authorize &lt;mcpxss-canary-abc123&gt;</h1></body></html>";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, null, MARKER);

        assertThat(verdict.context()).isEqualTo(ConsentReflectionAnalyzer.ReflectionContext.ENTITY_ENCODED);
    }

    @Test
    void strippedTagsLeaveOnlyTextIsStrippedContext() {
        // Tag brackets removed, the canary name text survives, but the literal <...> tag does not.
        String html = "<html><body><h1>Authorize mcpxss-canary-abc123</h1></body></html>";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, null, MARKER);

        assertThat(verdict.context()).isEqualTo(ConsentReflectionAnalyzer.ReflectionContext.STRIPPED);
    }

    @Test
    void markerSurvivingOnlyInsideHtmlCommentIsNotExecutable() {
        // The canary marker lands inside an HTML comment and does NOT break out of it: the browser
        // never parses it as a tag, so it is not executable. Must NOT be a raw breakout.
        String html = "<html><body><!-- debug: client_name=" + MARKER + " --></body></html>";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, null, MARKER);

        assertThat(verdict.context()).isEqualTo(ConsentReflectionAnalyzer.ReflectionContext.HTML_COMMENT);
        assertThat(verdict.isRawBreakout()).isFalse();
    }

    @Test
    void markerThatBreaksOutOfHtmlCommentIsExecutable() {
        // The canary contains the comment-closing sequence, so the marker tag lands AFTER the
        // comment closes — back in body parsing context. That IS a raw breakout.
        String html = "<html><body><!-- note --><h1>" + MARKER + "</h1></body></html>";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, null, MARKER);

        assertThat(verdict.context()).isEqualTo(ConsentReflectionAnalyzer.ReflectionContext.RAW_BODY_OR_ATTRIBUTE);
        assertThat(verdict.isRawBreakout()).isTrue();
    }

    @Test
    void absentMarkerIsAbsentContext() {
        String html = "<html><body><h1>Authorize this application</h1></body></html>";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, null, MARKER);

        assertThat(verdict.context()).isEqualTo(ConsentReflectionAnalyzer.ReflectionContext.ABSENT);
    }

    @Test
    void rawMarkerWithUnsafeInlineCspDoesNotMitigate() {
        String html = "<html><body>" + MARKER + "</body></html>";
        String csp = "default-src 'self'; script-src 'self' 'unsafe-inline'";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, csp, MARKER);

        assertThat(verdict.context()).isEqualTo(ConsentReflectionAnalyzer.ReflectionContext.RAW_BODY_OR_ATTRIBUTE);
        assertThat(verdict.cspMitigates()).isFalse();
    }

    @Test
    void rawMarkerWithStrictScriptSrcCspMitigates() {
        String html = "<html><body>" + MARKER + "</body></html>";
        String csp = "default-src 'self'; script-src 'self'";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, csp, MARKER);

        assertThat(verdict.cspMitigates()).isTrue();
    }

    @Test
    void strictDefaultSrcWithoutScriptSrcMitigates() {
        String html = "<html><body>" + MARKER + "</body></html>";
        String csp = "default-src 'self'";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, csp, MARKER);

        assertThat(verdict.cspMitigates()).isTrue();
    }

    @Test
    void scriptSrcWildcardDoesNotMitigate() {
        String html = "<html><body>" + MARKER + "</body></html>";
        String csp = "script-src *";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, csp, MARKER);

        assertThat(verdict.cspMitigates()).isFalse();
    }

    @Test
    void absentCspDoesNotMitigate() {
        String html = "<html><body>" + MARKER + "</body></html>";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, null, MARKER);

        assertThat(verdict.cspMitigates()).isFalse();
    }

    @Test
    void unsafeInlineUnderDefaultSrcFallbackDoesNotMitigate() {
        // No script-src, so default-src is the effective script source — and it has unsafe-inline.
        String html = "<html><body>" + MARKER + "</body></html>";
        String csp = "default-src 'self' 'unsafe-inline'";

        ConsentReflectionAnalyzer.Verdict verdict = analyzer.analyze(html, csp, MARKER);

        assertThat(verdict.cspMitigates()).isFalse();
    }

    @Test
    void rawReflectionReportsRawBreakoutForScriptAndBodyContexts() {
        String script = "<script>" + MARKER + "</script>";
        String body = "<body>" + MARKER + "</body>";

        assertThat(analyzer.analyze(script, null, MARKER).isRawBreakout()).isTrue();
        assertThat(analyzer.analyze(body, null, MARKER).isRawBreakout()).isTrue();
        assertThat(analyzer.analyze("&lt;mcpxss-canary-abc123&gt;", null, MARKER).isRawBreakout()).isFalse();
    }
}
