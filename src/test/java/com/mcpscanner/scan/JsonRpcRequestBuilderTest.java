package com.mcpscanner.scan;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.JsonRpcRequestBuilder.RawRequestWithOffsets;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JsonRpcRequestBuilderTest {

    private JsonRpcRequestBuilder builder;

    @BeforeAll
    static void installMontoya() {
        MontoyaTestFactory.install();
    }

    @BeforeEach
    void setUp() {
        builder = new JsonRpcRequestBuilder();
    }

    @Nested
    class BuildRawOffsetComputation {

        private static final String ENDPOINT = "https://example.com:8443/mcp/v1";

        @Test
        void singleStringParamOffsetExtractsCorrectValue() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"test\"}", Map.of());

            InsertionPointOffset offset = findOffset(result, "msg");
            String extracted = result.rawHttpRequest().substring(offset.startInclusive(), offset.endExclusive());
            assertThat(extracted).isEqualTo("test");
        }

        @Test
        void singleIntegerParamOffsetExtractsCorrectValue() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "calculate", "{\"value\":\"1\"}", Map.of());

            InsertionPointOffset offset = findOffset(result, "value");
            String extracted = result.rawHttpRequest().substring(offset.startInclusive(), offset.endExclusive());
            assertThat(extracted).isEqualTo("1");
        }

        @Test
        void singleBooleanParamOffsetExtractsCorrectValue() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "toggle", "{\"flag\":\"true\"}", Map.of());

            InsertionPointOffset offset = findOffset(result, "flag");
            String extracted = result.rawHttpRequest().substring(offset.startInclusive(), offset.endExclusive());
            assertThat(extracted).isEqualTo("true");
        }

        @Test
        void multipleParamsEachOffsetExtractsCorrectValue() {
            String args = "{\"name\":\"test\",\"count\":\"1\",\"active\":\"true\"}";
            RawRequestWithOffsets result = builder.buildRaw(ENDPOINT, "multi", args, Map.of());

            String rawRequest = result.rawHttpRequest();

            InsertionPointOffset nameOffset = findOffset(result, "name");
            assertThat(rawRequest.substring(nameOffset.startInclusive(), nameOffset.endExclusive()))
                    .isEqualTo("test");

            InsertionPointOffset countOffset = findOffset(result, "count");
            assertThat(rawRequest.substring(countOffset.startInclusive(), countOffset.endExclusive()))
                    .isEqualTo("1");

            InsertionPointOffset activeOffset = findOffset(result, "active");
            assertThat(rawRequest.substring(activeOffset.startInclusive(), activeOffset.endExclusive()))
                    .isEqualTo("true");
        }

        @Test
        void arrayAndObjectParamsProduceNoOffsets() {
            String args = "{\"items\":[],\"config\":{},\"name\":\"test\"}";
            RawRequestWithOffsets result = builder.buildRaw(ENDPOINT, "mixed", args, Map.of());

            assertThat(result.offsets()).hasSize(1);
            assertThat(result.offsets().get(0).parameterName()).isEqualTo("name");
        }

        @Test
        void rawRequestStartsWithPost() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"test\"}", Map.of());

            assertThat(result.rawHttpRequest()).startsWith("POST /mcp/v1 HTTP/1.1\r\n");
        }

        @Test
        void rawRequestContainsContentTypeHeader() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"test\"}", Map.of());

            assertThat(result.rawHttpRequest()).contains("Content-Type: application/json\r\n");
        }

        @Test
        void rawRequestContainsCorrectHostHeader() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"test\"}", Map.of());

            assertThat(result.rawHttpRequest()).contains("Host: example.com:8443\r\n");
        }

        @Test
        void rawRequestContainsCorrectHostHeaderForDefaultPort() {
            RawRequestWithOffsets result = builder.buildRaw(
                    "https://example.com/api", "echo", "{\"msg\":\"test\"}", Map.of());

            assertThat(result.rawHttpRequest()).contains("Host: example.com\r\n");
        }

        @Test
        void nonAuthorizationHeadersAppearInRequest() {
            Map<String, String> authHeaders = new LinkedHashMap<>();
            authHeaders.put("X-Api-Key", "key456");

            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"test\"}", authHeaders);

            assertThat(result.rawHttpRequest()).contains("X-Api-Key: key456\r\n");
        }

        @Test
        void authorizationHeaderIsStrippedSoProxyCanInjectFreshSessionToken() {
            Map<String, String> authHeaders = new LinkedHashMap<>();
            authHeaders.put("Authorization", "Bearer stale-token-baked-into-bytes");
            authHeaders.put("X-Api-Key", "key456");

            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"test\"}", authHeaders);

            assertThat(result.rawHttpRequest()).doesNotContain("Authorization");
            assertThat(result.rawHttpRequest()).contains("X-Api-Key: key456\r\n");
        }

        @Test
        void authorizationHeaderIsStrippedCaseInsensitively() {
            Map<String, String> authHeaders = new LinkedHashMap<>();
            authHeaders.put("authorization", "Bearer stale");

            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"test\"}", authHeaders);

            assertThat(result.rawHttpRequest()).doesNotContainIgnoringCase("authorization");
        }

        @Test
        void jsonRpcBodyContainsRequiredFields() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "myTool", "{\"msg\":\"test\"}", Map.of());

            String body = extractBody(result.rawHttpRequest());
            assertThat(body).contains("\"jsonrpc\":\"2.0\"");
            assertThat(body).contains("\"id\":1");
            assertThat(body).contains("\"method\":\"tools/call\"");
            assertThat(body).contains("\"name\":\"myTool\"");
            assertThat(body).contains("\"arguments\":{\"msg\":\"test\"}");
        }

        @Test
        void emptyArgumentsProducesNoOffsets() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "noop", "{}", Map.of());

            assertThat(result.offsets()).isEmpty();
        }

        @Test
        void overlappingKeyPrefixesExtractCorrectValues() {
            String args = "{\"a\":\"test\",\"ba\":\"other\"}";
            RawRequestWithOffsets result = builder.buildRaw(ENDPOINT, "overlap", args, Map.of());

            String rawRequest = result.rawHttpRequest();

            InsertionPointOffset aOffset = findOffset(result, "a");
            assertThat(rawRequest.substring(aOffset.startInclusive(), aOffset.endExclusive()))
                    .isEqualTo("test");

            InsertionPointOffset baOffset = findOffset(result, "ba");
            assertThat(rawRequest.substring(baOffset.startInclusive(), baOffset.endExclusive()))
                    .isEqualTo("other");
        }

        @Test
        void rawRequestContainsAcceptHeader() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"test\"}", Map.of());

            assertThat(result.rawHttpRequest())
                    .contains("Accept: application/json, text/event-stream\r\n");
        }

        @Test
        void endpointWithQueryStringIncludesQueryInRequestLine() {
            RawRequestWithOffsets result = builder.buildRaw(
                    "http://localhost:3001/message?sessionId=abc-123", "echo", "{\"msg\":\"test\"}", Map.of());

            assertThat(result.rawHttpRequest()).startsWith("POST /message?sessionId=abc-123 HTTP/1.1\r\n");
        }

        @Test
        void endpointWithoutQueryStringOmitsQuestionMark() {
            RawRequestWithOffsets result = builder.buildRaw(
                    "http://localhost:3001/mcp", "echo", "{\"msg\":\"test\"}", Map.of());

            assertThat(result.rawHttpRequest()).startsWith("POST /mcp HTTP/1.1\r\n");
        }

        @Test
        void buildDoesNotThrowForValidEndpoint() {
            AuthStrategy noAuth = Map::of;

            assertThatCode(() -> builder.build(ENDPOINT, "echo", "{\"msg\":\"test\"}", noAuth))
                    .doesNotThrowAnyException();
        }

        @Test
        void buildReturnsNonNullRequestAndOffsets() {
            AuthStrategy noAuth = Map::of;

            var result = builder.build(ENDPOINT, "echo", "{\"msg\":\"test\"}", noAuth);

            assertThat(result.request()).isNotNull();
            assertThat(result.offsets()).isNotEmpty();
        }

        private InsertionPointOffset findOffset(RawRequestWithOffsets result, String parameterName) {
            return result.offsets().stream()
                    .filter(o -> o.parameterName().equals(parameterName))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("No offset found for: " + parameterName));
        }

        private String extractBody(String rawRequest) {
            int bodyStart = rawRequest.indexOf("\r\n\r\n");
            return rawRequest.substring(bodyStart + 4);
        }
    }

    @Nested
    class ByteOffsetCorrectness {

        private static final String ENDPOINT = "https://example.com/api";

        @Test
        void contentLengthIsUtf8ByteCountForMultibyteBody() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"héllo\"}", Map.of());

            String raw = result.rawHttpRequest();
            String body = raw.substring(raw.indexOf("\r\n\r\n") + 4);
            int declaredContentLength = parseContentLength(raw);

            assertThat(declaredContentLength)
                    .isEqualTo(body.getBytes(StandardCharsets.UTF_8).length)
                    .isNotEqualTo(body.length());
        }

        @Test
        void argumentOffsetsArePositionedAtUtf8Bytes() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"msg\":\"héllo\"}", Map.of());

            byte[] requestBytes = result.rawHttpRequest().getBytes(StandardCharsets.UTF_8);
            InsertionPointOffset offset = findOffset(result, "msg");

            byte[] sliced = Arrays.copyOfRange(requestBytes, offset.startInclusive(), offset.endExclusive());
            assertThat(new String(sliced, StandardCharsets.UTF_8)).isEqualTo("héllo");
        }

        @Test
        void laterArgumentOffsetIsCorrectAfterMultibyteValue() {
            RawRequestWithOffsets result = builder.buildRaw(
                    ENDPOINT, "echo", "{\"first\":\"é\",\"second\":\"x\"}", Map.of());

            byte[] requestBytes = result.rawHttpRequest().getBytes(StandardCharsets.UTF_8);
            InsertionPointOffset second = findOffset(result, "second");

            byte[] sliced = Arrays.copyOfRange(requestBytes, second.startInclusive(), second.endExclusive());
            assertThat(new String(sliced, StandardCharsets.UTF_8)).isEqualTo("x");
        }

        @Test
        void escapedKeyArgumentIsLocatedCorrectly() {
            String args = McpObjectMapper.INSTANCE.valueToTree(Map.of("a\"b", "v")).toString();

            RawRequestWithOffsets result = builder.buildRaw(ENDPOINT, "echo", args, Map.of());

            byte[] requestBytes = result.rawHttpRequest().getBytes(StandardCharsets.UTF_8);
            InsertionPointOffset offset = findOffset(result, "a\"b");

            byte[] sliced = Arrays.copyOfRange(requestBytes, offset.startInclusive(), offset.endExclusive());
            assertThat(new String(sliced, StandardCharsets.UTF_8)).isEqualTo("v");
        }

        private int parseContentLength(String rawRequest) {
            for (String line : rawRequest.split("\r\n")) {
                if (line.regionMatches(true, 0, "Content-Length:", 0, "Content-Length:".length())) {
                    return Integer.parseInt(line.substring("Content-Length:".length()).trim());
                }
            }
            throw new AssertionError("No Content-Length header in: " + rawRequest);
        }

        private InsertionPointOffset findOffset(RawRequestWithOffsets result, String parameterName) {
            return result.offsets().stream()
                    .filter(o -> o.parameterName().equals(parameterName))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("No offset found for: " + parameterName));
        }
    }

    @Nested
    class HeaderValidation {

        private static final String ENDPOINT = "https://example.com/api";

        @Test
        void headerValueWithCarriageReturnIsRejected() {
            Map<String, String> badHeaders = Map.of("X-Foo", "bar\r\nX-Smuggle: yes");

            assertThatThrownBy(() ->
                    builder.buildRaw(ENDPOINT, "echo", "{\"msg\":\"test\"}", badHeaders))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void headerValueWithLineFeedIsRejected() {
            Map<String, String> badHeaders = Map.of("X-Foo", "line1\nline2");

            assertThatThrownBy(() ->
                    builder.buildRaw(ENDPOINT, "echo", "{\"msg\":\"test\"}", badHeaders))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void headerValueWithNullByteIsRejected() {
            Map<String, String> badHeaders = Map.of("X-Foo", "evil\0value");

            assertThatThrownBy(() ->
                    builder.buildRaw(ENDPOINT, "echo", "{\"msg\":\"test\"}", badHeaders))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void headerNameWithSpaceIsRejected() {
            Map<String, String> badHeaders = Map.of("X Foo", "value");

            assertThatThrownBy(() ->
                    builder.buildRaw(ENDPOINT, "echo", "{\"msg\":\"test\"}", badHeaders))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void headerNameWithCrlfIsRejected() {
            Map<String, String> badHeaders = Map.of("X-Foo\r\nEvil", "value");

            assertThatThrownBy(() ->
                    builder.buildRaw(ENDPOINT, "echo", "{\"msg\":\"test\"}", badHeaders))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void wellFormedHeadersAreAccepted() {
            Map<String, String> okHeaders = Map.of("Authorization", "Bearer token-with.dots_and-dashes");

            assertThatCode(() ->
                    builder.buildRaw(ENDPOINT, "echo", "{\"msg\":\"test\"}", okHeaders))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    class PromptGet {

        private static final String ENDPOINT = "https://example.com/mcp";

        @Test
        void bodyContainsPromptsGetMethodAndPromptName() {
            RawRequestWithOffsets result = builder.buildPromptGetRaw(
                    ENDPOINT, "summarize", "{\"topic\":\"weather\"}", Map.of());

            String body = extractBody(result.rawHttpRequest());
            assertThat(body).contains("\"method\":\"prompts/get\"");
            assertThat(body).contains("\"name\":\"summarize\"");
            assertThat(body).contains("\"arguments\":{\"topic\":\"weather\"}");
        }

        @Test
        void offsetExtractsArgumentValuesWithoutQuotes() {
            RawRequestWithOffsets result = builder.buildPromptGetRaw(
                    ENDPOINT, "summarize", "{\"topic\":\"weather\",\"detail\":\"high\"}", Map.of());

            InsertionPointOffset topicOffset = findOffset(result, "topic");
            InsertionPointOffset detailOffset = findOffset(result, "detail");

            assertThat(result.rawHttpRequest().substring(topicOffset.startInclusive(), topicOffset.endExclusive()))
                    .isEqualTo("weather");
            assertThat(result.rawHttpRequest().substring(detailOffset.startInclusive(), detailOffset.endExclusive()))
                    .isEqualTo("high");
        }

        @Test
        void emptyArgumentsProducesNoOffsets() {
            RawRequestWithOffsets result = builder.buildPromptGetRaw(
                    ENDPOINT, "no-args", "{}", Map.of());

            assertThat(result.offsets()).isEmpty();
        }

        @Test
        void buildPromptGetProducesNonNullRequest() {
            var result = builder.buildPromptGet(
                    ENDPOINT, "summarize", "{\"topic\":\"weather\"}", Map.of());

            assertThat(result.request()).isNotNull();
            assertThat(result.offsets()).isNotEmpty();
        }
    }

    @Nested
    class ResourceRead {

        private static final String ENDPOINT = "https://example.com/mcp";

        @Test
        void bodyContainsResourcesReadMethodAndUri() {
            RawRequestWithOffsets result = builder.buildResourceReadRaw(
                    ENDPOINT, "file:///etc/passwd", Map.of());

            String body = extractBody(result.rawHttpRequest());
            assertThat(body).contains("\"method\":\"resources/read\"");
            assertThat(body).contains("\"uri\":\"file:///etc/passwd\"");
        }

        @Test
        void uriOffsetExtractsContentWithoutSurroundingQuotes() {
            RawRequestWithOffsets result = builder.buildResourceReadRaw(
                    ENDPOINT, "file:///etc/passwd", Map.of());

            InsertionPointOffset offset = findOffset(result, "uri");
            String extracted = result.rawHttpRequest().substring(offset.startInclusive(), offset.endExclusive());

            assertThat(extracted).isEqualTo("file:///etc/passwd");
        }

        @Test
        void singleInsertionPointReturned() {
            RawRequestWithOffsets result = builder.buildResourceReadRaw(
                    ENDPOINT, "scheme://host", Map.of());

            assertThat(result.offsets()).hasSize(1);
            assertThat(result.offsets().get(0).parameterName()).isEqualTo("uri");
        }

        @Test
        void buildResourceReadProducesNonNullRequest() {
            var result = builder.buildResourceRead(ENDPOINT, "file:///x", Map.of());

            assertThat(result.request()).isNotNull();
            assertThat(result.offsets()).hasSize(1);
        }
    }

    @Nested
    class ResourceTemplateRead {

        private static final String ENDPOINT = "https://example.com/mcp";

        @Test
        void bodyContainsExpandedUriWithVariableNamesSubstituted() {
            RawRequestWithOffsets result = builder.buildResourceTemplateReadRaw(
                    ENDPOINT, "file:///{path}", Map.of());

            String body = extractBody(result.rawHttpRequest());
            assertThat(body).contains("\"uri\":\"file:///path\"");
        }

        @Test
        void perVariableOffsetsPointAtSubstitutedNameInExpandedUri() {
            RawRequestWithOffsets result = builder.buildResourceTemplateReadRaw(
                    ENDPOINT, "db://{server}/{database}/{table}", Map.of());

            String rawRequest = result.rawHttpRequest();
            InsertionPointOffset serverOffset = findOffset(result, "server");
            InsertionPointOffset databaseOffset = findOffset(result, "database");
            InsertionPointOffset tableOffset = findOffset(result, "table");

            assertThat(rawRequest.substring(serverOffset.startInclusive(), serverOffset.endExclusive()))
                    .isEqualTo("server");
            assertThat(rawRequest.substring(databaseOffset.startInclusive(), databaseOffset.endExclusive()))
                    .isEqualTo("database");
            assertThat(rawRequest.substring(tableOffset.startInclusive(), tableOffset.endExclusive()))
                    .isEqualTo("table");
        }

        @Test
        void templateWithoutPlaceholdersProducesNoOffsets() {
            RawRequestWithOffsets result = builder.buildResourceTemplateReadRaw(
                    ENDPOINT, "file:///static", Map.of());

            assertThat(result.offsets()).isEmpty();
        }

        @Test
        void offsetsAreUtf8ByteCorrectForTemplateWithMultibyteLiterals() {
            RawRequestWithOffsets result = builder.buildResourceTemplateReadRaw(
                    ENDPOINT, "héllo/{name}", Map.of());

            byte[] requestBytes = result.rawHttpRequest().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            InsertionPointOffset offset = findOffset(result, "name");

            byte[] sliced = java.util.Arrays.copyOfRange(
                    requestBytes, offset.startInclusive(), offset.endExclusive());
            assertThat(new String(sliced, java.nio.charset.StandardCharsets.UTF_8)).isEqualTo("name");
        }
    }

    private static InsertionPointOffset findOffset(RawRequestWithOffsets result, String parameterName) {
        return result.offsets().stream()
                .filter(o -> o.parameterName().equals(parameterName))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No offset found for: " + parameterName));
    }

    private static String extractBody(String rawRequest) {
        int bodyStart = rawRequest.indexOf("\r\n\r\n");
        return rawRequest.substring(bodyStart + 4);
    }
}
