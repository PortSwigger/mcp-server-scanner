package com.mcpscanner.checks.catalog.filetraversal;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class TraversalReplyTest {

    private static final HttpRequest REQUEST = PathArgumentInsertionPoint.toolCall("x");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void collectsToolTextResourceTextPromptTextAndErrorMessages() {
        TraversalReply tool = reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"a\"}]}}");
        TraversalReply resource = reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"contents\":[{\"uri\":\"x\",\"text\":\"b\"}]}}");
        TraversalReply prompt = reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"messages\":[{\"content\":{\"text\":\"c\"}}]}}");
        TraversalReply error = reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"d\"}}");

        assertThat(tool.texts()).contains("a");
        assertThat(resource.texts()).contains("b");
        assertThat(prompt.texts()).contains("c");
        assertThat(error.texts()).contains("d");
        assertThat(error.failed()).isTrue();
    }

    @Test
    void decodesJsonCarriedInsideATextField() {
        TraversalReply reply = reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\","
                + "\"text\":\"{\\\"content\\\":\\\"[core]\\\\nrepositoryformatversion = 0\\\\n\\\"}\"}]}}");

        assertThat(reply.texts()).contains("[core]\nrepositoryformatversion = 0\n");
    }

    @Test
    void decodesBase64Blobs() {
        String blob = Base64.getEncoder().encodeToString("root:x:0:0:root:/root:/bin/sh".getBytes());
        TraversalReply reply = reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"contents\":[{\"uri\":\"x\",\"blob\":\""
                + blob + "\"}]}}");

        assertThat(reply.texts()).contains("root:x:0:0:root:/root:/bin/sh");
    }

    @Test
    void readsTheReplyAfterAServerPingCarryingAnId() {
        HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                + "data: {\"jsonrpc\":\"2.0\",\"id\":\"s1\",\"method\":\"ping\"}\n\n"
                + "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[{\"text\":\"f\"}]}}\n\n");

        TraversalReply reply = TraversalReply.of(HttpRequestResponse.httpRequestResponse(REQUEST, response));

        assertThat(reply.answered()).isTrue();
        assertThat(reply.texts()).contains("f");
    }

    @Test
    void liftsAnSseFramedReply() {
        HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"text\":\"e\"}]}}\n\n");

        assertThat(TraversalReply.of(HttpRequestResponse.httpRequestResponse(REQUEST, response)).texts()).contains("e");
    }

    @Test
    void marksToolErrorsAsFailedAndMethodNotFoundSeparately() {
        assertThat(reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true,\"content\":[]}}").failed()).isTrue();
        assertThat(reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"x\"}}")
                .methodNotFound()).isTrue();
    }

    @Test
    void treatsMissingNonJsonOrEnvelopeLessRepliesAsUnanswered() {
        assertThat(TraversalReply.of(HttpRequestResponse.httpRequestResponse(REQUEST, null)).answered()).isFalse();
        assertThat(reply("not json").answered()).isFalse();
        assertThat(reply("{\"jsonrpc\":\"2.0\",\"id\":1}").answered()).isFalse();
    }

    @Test
    void rejectedNeedsAnAnsweredFailureOrDenialThatIsNotARoutingMiss() {
        assertThat(reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true,\"content\":[]}}").rejected()).isTrue();
        assertThat(reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"contents\":[{\"text\":\"Error: Access denied\"}]}}")
                .rejected()).isTrue();
        assertThat(reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"no\"}}").rejected()).isFalse();
        assertThat(reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"text\":\"fine\"}]}}").rejected()).isFalse();
        assertThat(reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true,\"content\":[{\"text\":\"ENOENT: no such file\"}]}}")
                .rejected()).isFalse();
    }

    static TraversalReply reply(String body) {
        HttpResponse response = HttpResponse.httpResponse(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body);
        return TraversalReply.of(HttpRequestResponse.httpRequestResponse(REQUEST, response));
    }
}
