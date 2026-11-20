package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReplySignatureTest {

    private final ReplySignature signatures = new ReplySignature(new PayloadMask());

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void aChunkFramedFailureBodyHasTheSameSignatureAsTheUnframedBody() {
        HttpRequestResponse chunked = wire("Transfer-Encoding: chunked\r\n\r\n4\r\ngone\r\n0\r\n\r\n");
        HttpRequestResponse plain = wire("Content-Length: 4\r\n\r\ngone");

        assertThat(signatures.of(chunked, "../")).isEqualTo(signatures.of(plain, "../"));
    }

    private static HttpRequestResponse wire(String headTailAndBody) {
        HttpResponse response = HttpResponse.httpResponse(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n" + headTailAndBody);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(exchange.response()).thenReturn(response);
        return exchange;
    }

    @Test
    void successfulToolResultHasASuccessSignature() {
        assertThat(signatures.ofSuccess(Replies.toolText("{\"service\":\"index\"}"), "../")).isPresent();
    }

    @Test
    void toolErrorRpcErrorNonOkStatusAndMissingResponseHaveNoSuccessSignature() {
        assertThat(signatures.ofSuccess(Replies.toolError("denied"), "../")).isEmpty();
        assertThat(signatures.ofSuccess(Replies.rpcError("bad"), "../")).isEmpty();
        assertThat(signatures.ofSuccess(Replies.json(500, "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}"), "../"))
                .isEmpty();
        assertThat(signatures.ofSuccess(Replies.noResponse(), "../")).isEmpty();
        assertThat(signatures.ofSuccess(Replies.json(200, "not json"), "../")).isEmpty();
    }

    @Test
    void requestIdAndResultMetaDoNotChangeTheSignature() {
        String first = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[],\"_meta\":{\"t\":1}}}";
        String second = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[],\"_meta\":{\"t\":2}}}";
        assertThat(signatures.ofSuccess(Replies.json(200, first), "../"))
                .isEqualTo(signatures.ofSuccess(Replies.json(200, second), "../"));
    }

    @Test
    void sseFramedReplyIsReadLikeJson() {
        String sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[{\"type\":\"text\","
                + "\"text\":\"ok\"}],\"isError\":false}}\n\n";
        assertThat(signatures.ofSuccess(Replies.exchange(200, "text/event-stream", sse), "../"))
                .isEqualTo(signatures.ofSuccess(Replies.toolText("ok"), "../"));
    }

    @Test
    void anySignatureDistinguishesErrorsFromSuccess() {
        assertThat(signatures.of(Replies.toolError("not found"), "...")).isNotEqualTo(signatures.of(
                Replies.toolText("not found"), "..."));
        assertThat(signatures.of(Replies.noResponse(), "...")).isNotEqualTo(signatures.of(
                Replies.json(404, "gone"), "..."));
    }

    @Test
    void successfulReplyHasTheSameSignatureEitherWay() {
        assertThat(signatures.of(Replies.toolText("index"), "../"))
                .isEqualTo(signatures.ofSuccess(Replies.toolText("index"), "../").orElseThrow());
    }

    @Test
    void anySignatureMasksEchoedValues() {
        assertThat(signatures.of(Replies.toolError("no item .../"), ".../"))
                .isEqualTo(signatures.of(Replies.toolError("no item ..././"), "..././"));
    }
}
