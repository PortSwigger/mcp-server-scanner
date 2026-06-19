package com.mcpscanner.scan;

import com.mcpscanner.scan.ArgumentsObjectLocator.ArgumentsObjectRange;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ArgumentsObjectLocatorTest {

    @Nested
    class HappyPath {

        @Test
        void rangeCoversArgumentsObjectInToolsCallBody() {
            byte[] body = utf8("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                    + "\"params\":{\"name\":\"echo\",\"arguments\":{\"msg\":\"hello\"}}}");

            ArgumentsObjectRange range = ArgumentsObjectLocator.locate(body).orElseThrow();

            assertThat(slice(body, range)).isEqualTo("{\"msg\":\"hello\"}");
        }

        @Test
        void rangeCoversEmptyArgumentsObject() {
            byte[] body = utf8("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                    + "\"params\":{\"name\":\"noop\",\"arguments\":{}}}");

            ArgumentsObjectRange range = ArgumentsObjectLocator.locate(body).orElseThrow();

            assertThat(slice(body, range)).isEqualTo("{}");
        }

        @Test
        void rangeCoversArgumentsWithNestedObjectsAndArrays() {
            byte[] body = utf8("{\"params\":{\"arguments\":{\"o\":{\"k\":1},\"a\":[1,2],\"s\":\"x\"}}}");

            ArgumentsObjectRange range = ArgumentsObjectLocator.locate(body).orElseThrow();

            assertThat(slice(body, range)).isEqualTo("{\"o\":{\"k\":1},\"a\":[1,2],\"s\":\"x\"}");
        }

        @Test
        void rangeEndIsClampedToClosingBraceByte() {
            byte[] body = utf8("{\"params\":{\"arguments\":{\"msg\":\"hello\"}}}");

            ArgumentsObjectRange range = ArgumentsObjectLocator.locate(body).orElseThrow();

            assertThat(body[range.end() - 1]).isEqualTo((byte) '}');
        }

        @Test
        void rangeStartIsOpeningBraceByte() {
            byte[] body = utf8("{\"params\":{\"arguments\":{\"msg\":\"hello\"}}}");

            ArgumentsObjectRange range = ArgumentsObjectLocator.locate(body).orElseThrow();

            assertThat(body[range.start()]).isEqualTo((byte) '{');
        }

        @Test
        void handlesWhitespaceBetweenColonAndOpeningBrace() {
            byte[] body = utf8("{\"params\":{\"arguments\" : {\"msg\":\"hello\"}}}");

            ArgumentsObjectRange range = ArgumentsObjectLocator.locate(body).orElseThrow();

            assertThat(slice(body, range)).isEqualTo("{\"msg\":\"hello\"}");
        }
    }

    @Nested
    class AbsentOrInvalid {

        @Test
        void emptyForBodyWithoutArgumentsField() {
            byte[] body = utf8("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                    + "\"params\":{\"name\":\"noop\"}}");

            Optional<ArgumentsObjectRange> range = ArgumentsObjectLocator.locate(body);

            assertThat(range).isEmpty();
        }

        @Test
        void emptyForMalformedJson() {
            byte[] body = utf8("{\"method\":\"tools/call\", invalid json}}");

            Optional<ArgumentsObjectRange> range = ArgumentsObjectLocator.locate(body);

            assertThat(range).isEmpty();
        }

        @Test
        void emptyForNonJsonBody() {
            byte[] body = utf8("This is not JSON but mentions arguments");

            Optional<ArgumentsObjectRange> range = ArgumentsObjectLocator.locate(body);

            assertThat(range).isEmpty();
        }

        @Test
        void emptyWhenArgumentsValueIsNotAnObject() {
            byte[] body = utf8("{\"params\":{\"arguments\":\"oops\"}}");

            Optional<ArgumentsObjectRange> range = ArgumentsObjectLocator.locate(body);

            assertThat(range).isEmpty();
        }

        @Test
        void emptyForEmptyBody() {
            Optional<ArgumentsObjectRange> range = ArgumentsObjectLocator.locate(new byte[0]);

            assertThat(range).isEmpty();
        }
    }

    @Nested
    class Utf8Bytes {

        @Test
        void rangeIsByteAccurateForMultibyteValues() {
            byte[] body = utf8("{\"params\":{\"arguments\":{\"msg\":\"héllo\"}}}");

            ArgumentsObjectRange range = ArgumentsObjectLocator.locate(body).orElseThrow();

            assertThat(slice(body, range)).isEqualTo("{\"msg\":\"héllo\"}");
        }
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String slice(byte[] bytes, ArgumentsObjectRange range) {
        return new String(Arrays.copyOfRange(bytes, range.start(), range.end()), StandardCharsets.UTF_8);
    }
}
