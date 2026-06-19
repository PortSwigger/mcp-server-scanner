package com.mcpscanner.scan;

import com.mcpscanner.scan.UriValueLocator.UriValueRange;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class UriValueLocatorTest {

    @Test
    void locatesUriInResourcesReadBody() {
        byte[] bytes = utf8(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"params\":{\"uri\":\"file:///etc/passwd\"}}");

        Optional<UriValueRange> range = UriValueLocator.locate(bytes);

        assertThat(range).isPresent();
        assertThat(slice(bytes, range.get())).isEqualTo("\"file:///etc/passwd\"");
    }

    @Test
    void rangeIncludesSurroundingQuotes() {
        byte[] bytes = utf8(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"params\":{\"uri\":\"x\"}}");

        UriValueRange range = UriValueLocator.locate(bytes).orElseThrow();

        assertThat(bytes[range.startInclusive()]).isEqualTo((byte) '"');
        assertThat(bytes[range.endExclusive() - 1]).isEqualTo((byte) '"');
    }

    @Test
    void handlesMultibyteUtf8InUri() {
        String uri = "file:///héllo";
        byte[] bytes = utf8(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"params\":{\"uri\":\"" + uri + "\"}}");

        UriValueRange range = UriValueLocator.locate(bytes).orElseThrow();

        assertThat(slice(bytes, range)).isEqualTo("\"" + uri + "\"");
    }

    @Test
    void returnsEmptyWhenParamsHasNoUriField() {
        byte[] bytes = utf8(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"params\":{\"name\":\"foo\"}}");

        assertThat(UriValueLocator.locate(bytes)).isEmpty();
    }

    @Test
    void returnsEmptyWhenParamsMissing() {
        byte[] bytes = utf8("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\"}");

        assertThat(UriValueLocator.locate(bytes)).isEmpty();
    }

    @Test
    void returnsEmptyForMalformedJson() {
        byte[] bytes = utf8("not json {{{");

        assertThat(UriValueLocator.locate(bytes)).isEmpty();
    }

    @Test
    void returnsEmptyForNullOrEmptyInput() {
        assertThat(UriValueLocator.locate(null)).isEmpty();
        assertThat(UriValueLocator.locate(new byte[0])).isEmpty();
    }

    @Test
    void ignoresNestedUriFieldOutsideParams() {
        byte[] bytes = utf8(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"meta\":{\"uri\":\"nope\"},"
                        + "\"params\":{\"uri\":\"real\"}}");

        UriValueRange range = UriValueLocator.locate(bytes).orElseThrow();

        assertThat(slice(bytes, range)).isEqualTo("\"real\"");
    }

    @Test
    void innerAccessorsTrimSurroundingQuotes() {
        byte[] bytes = utf8(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"params\":{\"uri\":\"file:///etc/passwd\"}}");

        UriValueRange range = UriValueLocator.locate(bytes).orElseThrow();

        String inner = new String(
                Arrays.copyOfRange(bytes, range.innerStartInclusive(), range.innerEndExclusive()),
                StandardCharsets.UTF_8);
        assertThat(inner).isEqualTo("file:///etc/passwd");
    }

    @Test
    void returnsEmptyWhenUriValueIsUnterminated() {
        // Jackson's streaming parser tolerates the truncated value token and yields a
        // VALUE_STRING, so the locator's own byte scan reaches findClosingQuote, which runs
        // off the end of the buffer and throws IllegalStateException ("Unterminated string").
        byte[] bytes = utf8("{\"params\":{\"uri\":\"unterminated}");

        assertThat(UriValueLocator.locate(bytes)).isEmpty();
    }

    @Test
    void skipsNonStringUriValues() {
        byte[] bytes = utf8(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"params\":{\"uri\":42}}");

        assertThat(UriValueLocator.locate(bytes)).isEmpty();
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String slice(byte[] bytes, UriValueRange range) {
        return new String(
                Arrays.copyOfRange(bytes, range.startInclusive(), range.endExclusive()),
                StandardCharsets.UTF_8);
    }
}
