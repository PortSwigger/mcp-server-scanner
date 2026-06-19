package com.mcpscanner.scan;

import com.mcpscanner.scan.ArgumentValueLocator.ValueByteRange;
import com.mcpscanner.scan.ArgumentValueLocator.ValueKind;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ArgumentValueLocatorTest {

    @Nested
    class PlainAscii {

        @Test
        void stringRangeIncludesQuotes() {
            byte[] bytes = utf8("{\"a\":\"v\",\"n\":1,\"b\":true}");

            Map<String, ValueByteRange> ranges = ArgumentValueLocator.locate(bytes);

            ValueByteRange a = ranges.get("a");
            assertThat(a.kind()).isEqualTo(ValueKind.STRING);
            assertThat(slice(bytes, a)).isEqualTo("\"v\"");
        }

        @Test
        void numberRangeCoversDigits() {
            byte[] bytes = utf8("{\"a\":\"v\",\"n\":1,\"b\":true}");

            ValueByteRange n = ArgumentValueLocator.locate(bytes).get("n");

            assertThat(n.kind()).isEqualTo(ValueKind.NUMBER);
            assertThat(slice(bytes, n)).isEqualTo("1");
        }

        @Test
        void booleanRangeCoversLiteral() {
            byte[] bytes = utf8("{\"a\":\"v\",\"n\":1,\"b\":true}");

            ValueByteRange b = ArgumentValueLocator.locate(bytes).get("b");

            assertThat(b.kind()).isEqualTo(ValueKind.BOOLEAN);
            assertThat(slice(bytes, b)).isEqualTo("true");
        }

        @Test
        void nullRangeCoversLiteral() {
            byte[] bytes = utf8("{\"x\":null}");

            ValueByteRange x = ArgumentValueLocator.locate(bytes).get("x");

            assertThat(x.kind()).isEqualTo(ValueKind.NULL);
            assertThat(slice(bytes, x)).isEqualTo("null");
        }

        @Test
        void preservesInsertionOrderOfKeys() {
            byte[] bytes = utf8("{\"first\":1,\"second\":2,\"third\":3}");

            Map<String, ValueByteRange> ranges = ArgumentValueLocator.locate(bytes);

            assertThat(ranges).containsExactly(
                    Map.entry("first", ranges.get("first")),
                    Map.entry("second", ranges.get("second")),
                    Map.entry("third", ranges.get("third")));
        }
    }

    @Nested
    class MultibyteUtf8 {

        @Test
        void stringValueWithMultibyteCharacterCoversExactBytes() {
            byte[] bytes = utf8("{\"a\":\"vé\"}");

            ValueByteRange a = ArgumentValueLocator.locate(bytes).get("a");

            assertThat(a.kind()).isEqualTo(ValueKind.STRING);
            byte[] expected = "\"vé\"".getBytes(StandardCharsets.UTF_8);
            assertThat(expected).hasSize(5); // 2 quotes + 'v' (1) + 'é' (2 UTF-8 bytes)
            assertThat(sliceBytes(bytes, a)).isEqualTo(expected);
        }

        @Test
        void multibyteCharacterShiftsLaterValueOffsets() {
            byte[] bytes = utf8("{\"a\":\"é\",\"b\":\"x\"}");

            ValueByteRange b = ArgumentValueLocator.locate(bytes).get("b");

            assertThat(slice(bytes, b)).isEqualTo("\"x\"");
        }

        @Test
        void multibyteKeyIsMatchedCorrectly() {
            byte[] bytes = utf8("{\"é\":\"v\"}");

            Map<String, ValueByteRange> ranges = ArgumentValueLocator.locate(bytes);

            assertThat(ranges).containsKey("é");
            assertThat(slice(bytes, ranges.get("é"))).isEqualTo("\"v\"");
        }
    }

    @Nested
    class EscapedKeys {

        @Test
        void escapedQuoteInKeyIsReconstructed() {
            byte[] bytes = utf8("{\"a\\\"b\":\"v\"}");

            Map<String, ValueByteRange> ranges = ArgumentValueLocator.locate(bytes);

            assertThat(ranges).containsKey("a\"b");
            assertThat(slice(bytes, ranges.get("a\"b"))).isEqualTo("\"v\"");
        }

        @Test
        void escapedBackslashInKeyIsReconstructed() {
            byte[] bytes = utf8("{\"a\\\\b\":\"v\"}");

            Map<String, ValueByteRange> ranges = ArgumentValueLocator.locate(bytes);

            assertThat(ranges).containsKey("a\\b");
            assertThat(slice(bytes, ranges.get("a\\b"))).isEqualTo("\"v\"");
        }
    }

    @Nested
    class NestedAndArrayValues {

        @Test
        void objectValueRangeCoversBraces() {
            byte[] bytes = utf8("{\"o\":{\"k\":1}}");

            ValueByteRange o = ArgumentValueLocator.locate(bytes).get("o");

            assertThat(o.kind()).isEqualTo(ValueKind.OBJECT);
            assertThat(slice(bytes, o)).isEqualTo("{\"k\":1}");
        }

        @Test
        void arrayValueRangeCoversBrackets() {
            byte[] bytes = utf8("{\"a\":[1,2,3]}");

            ValueByteRange a = ArgumentValueLocator.locate(bytes).get("a");

            assertThat(a.kind()).isEqualTo(ValueKind.ARRAY);
            assertThat(slice(bytes, a)).isEqualTo("[1,2,3]");
        }
    }

    @Nested
    class InnerContentAccessors {

        @Test
        void stringRangeTrimsQuotesOnInnerAccessors() {
            byte[] bytes = utf8("{\"a\":\"hello\"}");

            ValueByteRange a = ArgumentValueLocator.locate(bytes).get("a");

            assertThat(a.kind()).isEqualTo(ValueKind.STRING);
            assertThat(sliceInner(bytes, a)).isEqualTo("hello");
        }

        @Test
        void numberRangeInnerAccessorsMatchOuter() {
            byte[] bytes = utf8("{\"n\":42}");

            ValueByteRange n = ArgumentValueLocator.locate(bytes).get("n");

            assertThat(n.innerStartInclusive()).isEqualTo(n.startInclusive());
            assertThat(n.innerEndExclusive()).isEqualTo(n.endExclusive());
        }

        @Test
        void booleanRangeInnerAccessorsMatchOuter() {
            byte[] bytes = utf8("{\"b\":true}");

            ValueByteRange b = ArgumentValueLocator.locate(bytes).get("b");

            assertThat(b.innerStartInclusive()).isEqualTo(b.startInclusive());
            assertThat(b.innerEndExclusive()).isEqualTo(b.endExclusive());
        }

        @Test
        void nullRangeInnerAccessorsMatchOuter() {
            byte[] bytes = utf8("{\"x\":null}");

            ValueByteRange x = ArgumentValueLocator.locate(bytes).get("x");

            assertThat(x.innerStartInclusive()).isEqualTo(x.startInclusive());
            assertThat(x.innerEndExclusive()).isEqualTo(x.endExclusive());
        }

        @Test
        void objectRangeInnerAccessorsMatchOuter() {
            byte[] bytes = utf8("{\"o\":{\"k\":1}}");

            ValueByteRange o = ArgumentValueLocator.locate(bytes).get("o");

            assertThat(o.innerStartInclusive()).isEqualTo(o.startInclusive());
            assertThat(o.innerEndExclusive()).isEqualTo(o.endExclusive());
        }

        @Test
        void arrayRangeInnerAccessorsMatchOuter() {
            byte[] bytes = utf8("{\"a\":[1,2]}");

            ValueByteRange a = ArgumentValueLocator.locate(bytes).get("a");

            assertThat(a.innerStartInclusive()).isEqualTo(a.startInclusive());
            assertThat(a.innerEndExclusive()).isEqualTo(a.endExclusive());
        }

        private String sliceInner(byte[] bytes, ValueByteRange range) {
            return new String(
                    Arrays.copyOfRange(bytes, range.innerStartInclusive(), range.innerEndExclusive()),
                    StandardCharsets.UTF_8);
        }
    }

    @Nested
    class NonObjectInput {

        @Test
        void arrayInputReturnsEmptyMap() {
            byte[] bytes = utf8("[1,2]");

            assertThat(ArgumentValueLocator.locate(bytes)).isEmpty();
        }

        @Test
        void scalarInputReturnsEmptyMap() {
            byte[] bytes = utf8("42");

            assertThat(ArgumentValueLocator.locate(bytes)).isEmpty();
        }

        @Test
        void emptyInputReturnsEmptyMap() {
            assertThat(ArgumentValueLocator.locate(new byte[0])).isEmpty();
        }

        @Test
        void malformedJsonReturnsEmptyMap() {
            byte[] bytes = utf8("{not json");

            assertThat(ArgumentValueLocator.locate(bytes)).isEmpty();
        }

        @Test
        void unterminatedStringValueReturnsEmptyMap() {
            byte[] bytes = unterminatedStringArguments();

            assertThat(ArgumentValueLocator.locate(bytes)).isEmpty();
        }

        @Test
        void unterminatedContainerValueReturnsEmptyMap() {
            byte[] bytes = unterminatedContainerArguments();

            assertThat(ArgumentValueLocator.locate(bytes)).isEmpty();
        }
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // Jackson's streaming parser accepts the truncated value token, so the locator's own
    // byte scan reaches findClosingQuote and throws IllegalStateException ("Unterminated string").
    private static byte[] unterminatedStringArguments() {
        return utf8("{\"x\":\"unterminated}");
    }

    // Truncated container: Jackson returns START_OBJECT, then findMatchingClose runs off the
    // end and throws IllegalStateException ("Unterminated container").
    private static byte[] unterminatedContainerArguments() {
        return utf8("{\"x\":{\"k\":1");
    }

    private static String slice(byte[] bytes, ValueByteRange range) {
        return new String(sliceBytes(bytes, range), StandardCharsets.UTF_8);
    }

    private static byte[] sliceBytes(byte[] bytes, ValueByteRange range) {
        return Arrays.copyOfRange(bytes, range.startInclusive(), range.endExclusive());
    }
}
