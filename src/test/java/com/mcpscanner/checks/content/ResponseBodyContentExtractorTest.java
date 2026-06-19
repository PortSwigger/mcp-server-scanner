package com.mcpscanner.checks.content;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.mcp.McpRequestDetector.ResponseContentKind;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

class ResponseBodyContentExtractorTest {

    @Test
    void toolCall_extractsTextContentWithToolNameAndFieldPath() {
        HttpRequestResponse rr = pair(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"deploy_status\"}}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":["
                        + "{\"type\":\"text\",\"text\":\"deployed\"}]}}",
                null);

        List<InspectedField> fields = ResponseBodyContentExtractor.extract(
                ResponseContentKind.TOOL_CALL, rr);

        assertThat(fields).singleElement().satisfies(field -> {
            assertThat(field.objectType()).isEqualTo(SourceObjectType.TOOL);
            assertThat(field.objectName()).isEqualTo("deploy_status");
            assertThat(field.fieldPath()).isEqualTo("content[0].text");
            assertThat(field.value()).isEqualTo("deployed");
        });
    }

    @Test
    void toolCall_extractsEmbeddedResourceText() {
        HttpRequestResponse rr = pair(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"fetch\"}}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":["
                        + "{\"type\":\"resource\",\"resource\":{\"text\":\"embedded secret\"}}]}}",
                null);

        List<InspectedField> fields = ResponseBodyContentExtractor.extract(
                ResponseContentKind.TOOL_CALL, rr);

        assertThat(fields).singleElement().satisfies(field -> {
            assertThat(field.fieldPath()).isEqualTo("content[0].resource.text");
            assertThat(field.value()).isEqualTo("embedded secret");
        });
    }

    @Test
    void toolCall_skipsNonTextContentItems() {
        HttpRequestResponse rr = pair(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"img\"}}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":["
                        + "{\"type\":\"image\",\"data\":\"base64==\"},"
                        + "{\"type\":\"text\",\"text\":\"keep\"}]}}",
                null);

        List<InspectedField> fields = ResponseBodyContentExtractor.extract(
                ResponseContentKind.TOOL_CALL, rr);

        assertThat(fields).singleElement()
                .satisfies(field -> assertThat(field.value()).isEqualTo("keep"));
    }

    @Test
    void resourceRead_extractsContentsTextWithUriAsObjectName() {
        HttpRequestResponse rr = pair(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"params\":{\"uri\":\"file:///srv/secret\"}}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"contents\":["
                        + "{\"text\":\"resource body\"}]}}",
                null);

        List<InspectedField> fields = ResponseBodyContentExtractor.extract(
                ResponseContentKind.RESOURCE_READ, rr);

        assertThat(fields).singleElement().satisfies(field -> {
            assertThat(field.objectType()).isEqualTo(SourceObjectType.RESOURCE);
            assertThat(field.objectName()).isEqualTo("file:///srv/secret");
            assertThat(field.fieldPath()).isEqualTo("contents[0].text");
            assertThat(field.value()).isEqualTo("resource body");
        });
    }

    @Test
    void resourceRead_skipsBlobContents() {
        HttpRequestResponse rr = pair(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"params\":{\"uri\":\"file:///x\"}}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"contents\":["
                        + "{\"blob\":\"AAAA\"}]}}",
                null);

        List<InspectedField> fields = ResponseBodyContentExtractor.extract(
                ResponseContentKind.RESOURCE_READ, rr);

        assertThat(fields).isEmpty();
    }

    @Test
    void promptGet_extractsMessageContentTextWithPromptNameAsObjectName() {
        HttpRequestResponse rr = pair(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\","
                        + "\"params\":{\"name\":\"review\"}}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"messages\":["
                        + "{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":\"prompt secret\"}}]}}",
                null);

        List<InspectedField> fields = ResponseBodyContentExtractor.extract(
                ResponseContentKind.PROMPT_GET, rr);

        assertThat(fields).singleElement().satisfies(field -> {
            assertThat(field.objectType()).isEqualTo(SourceObjectType.PROMPT);
            assertThat(field.objectName()).isEqualTo("review");
            assertThat(field.fieldPath()).isEqualTo("messages[0].content.text");
            assertThat(field.value()).isEqualTo("prompt secret");
        });
    }

    @Test
    void unwrapsSseFramedToolCallResponse() {
        HttpRequestResponse rr = pair(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"deploy\"}}",
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,"
                        + "\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"sse secret\"}]}}\n\n",
                "text/event-stream");

        List<InspectedField> fields = ResponseBodyContentExtractor.extract(
                ResponseContentKind.TOOL_CALL, rr);

        assertThat(fields).singleElement()
                .satisfies(field -> assertThat(field.value()).isEqualTo("sse secret"));
    }

    @Test
    void returnsEmptyForMalformedResult() {
        HttpRequestResponse rr = pair(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"x\"}}",
                "not json at all",
                null);

        assertThat(ResponseBodyContentExtractor.extract(ResponseContentKind.TOOL_CALL, rr))
                .isEmpty();
    }

    @Test
    void respectsByteCapWithoutHanging() {
        StringBuilder huge = new StringBuilder("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[");
        for (int i = 0; i < 5000; i++) {
            huge.append("{\"type\":\"text\",\"text\":\"")
                    .append("A".repeat(200))
                    .append("\"},");
        }
        huge.append("{\"type\":\"text\",\"text\":\"tail\"}]}}");
        HttpRequestResponse rr = pair(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"flood\"}}",
                huge.toString(),
                null);

        List<InspectedField> fields = ResponseBodyContentExtractor.extract(
                ResponseContentKind.TOOL_CALL, rr);

        int total = fields.stream().mapToInt(f -> f.value().length()).sum();
        assertThat(total).isLessThanOrEqualTo(512 * 1024);
    }

    private static HttpRequestResponse pair(String requestBody, String responseBody,
                                            String responseContentType) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpResponse resp = mock(HttpResponse.class);
        lenient().when(rr.request()).thenReturn(req);
        lenient().when(rr.response()).thenReturn(resp);
        lenient().when(req.bodyToString()).thenReturn(requestBody);
        lenient().when(resp.bodyToString()).thenReturn(responseBody);
        lenient().when(resp.headerValue("Content-Type")).thenReturn(responseContentType);
        return rr;
    }
}
