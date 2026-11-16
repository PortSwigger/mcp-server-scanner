package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.OutsideBurpRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StreamingFallbackTest {

    private static final String ENDPOINT = "https://mcp.example.test/mcp";
    private static final String STREAMED = "Streaming response received";

    private final Http burp = mock(Http.class);
    private RequestOptions options;
    private final List<HttpRequest> unstreamed = new ArrayList<>();
    private final HttpRequestResponse unstreamedExchange = mock(HttpRequestResponse.class);
    private final List<HttpRequest> rawSocket = new ArrayList<>();
    private final HttpRequestResponse rawSocketExchange = mock(HttpRequestResponse.class);
    private boolean rawSocketConnects = true;
    private StreamingFallback fallback;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        options = RequestOptions.requestOptions();
        fallback = new StreamingFallback(request -> {
            unstreamed.add(request);
            return Optional.of(unstreamedExchange);
        }, request -> {
            rawSocket.add(request);
            return rawSocketConnects ? Optional.of(rawSocketExchange) : Optional.empty();
        });
    }

    @Test
    void sendsThroughBurpWhileBurpAnswers() {
        HttpRequestResponse answered = mock(HttpRequestResponse.class);
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(answered);

        assertThat(fallback.send(burp, directProbe(), options)).isSameAs(answered);
        assertThat(unstreamed).isEmpty();
    }

    @Test
    void resendsAProbeBurpRefusedAsStreamedWithoutTheDirectDeliverySentinel() {
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException("Streaming response received"));

        assertThat(fallback.send(burp, directProbe(), options)).isSameAs(unstreamedExchange);
        assertThat(unstreamed).singleElement()
                .satisfies(request -> assertThat(request.hasHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER)).isFalse());
    }

    @Test
    void resendsAProbeTheScanCheckHttpRefusedAsStreamedWithoutAMessage() {
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new RuntimeException(new burp.StreamingRefusalStandIn()));

        assertThat(fallback.send(burp, directProbe(), options)).isSameAs(unstreamedExchange);
        assertThat(unstreamed).hasSize(1);
    }

    @Test
    void sendsLaterProbesToAnEndpointThatStreamsStraightToTheUnstreamingClient() {
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException("Streaming response received"));

        fallback.send(burp, directProbe(), options);
        fallback.send(burp, directProbe(), options);

        verify(burp, times(1)).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
        assertThat(unstreamed).hasSize(2);
    }

    @Test
    void otherBurpFailuresPropagate() {
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException("Connection refused"));

        assertThatThrownBy(() -> fallback.send(burp, directProbe(), options)).hasMessage("Connection refused");
        assertThat(unstreamed).isEmpty();
    }

    @Test
    void anHttpWrappedByTheFallbackRecoversAStreamedReplyToAPlainSend() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));

        assertThat(fallback.around(burp).sendRequest(routedProbe())).isSameAs(unstreamedExchange);
    }

    @Test
    void anHttpWrappedByTheFallbackSendsThroughBurpWhileBurpAnswers() {
        HttpRequestResponse answered = mock(HttpRequestResponse.class);
        when(burp.sendRequest(any(HttpRequest.class))).thenReturn(answered);

        assertThat(fallback.around(burp).sendRequest(routedProbe())).isSameAs(answered);
        assertThat(unstreamed).isEmpty();
    }

    @Test
    void removesEveryScannerSentinelBeforeTheProbeLeavesBurp() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));

        fallback.around(burp).sendRequest(routedProbe()
                .withHeader(ScannerSentinels.AUDIT_CAPABILITY_HEADER, "capability"));

        assertThat(unstreamed).singleElement().satisfies(request -> assertThat(request.headers())
                .noneMatch(header -> ScannerSentinels.ALL.contains(header.name())));
    }

    @Test
    void sendsAProbeWhoseHostHeaderNamesAnotherHostThroughTheRawSocketClient() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));

        HttpRequestResponse exchange = fallback.around(burp).sendRequest(routedProbe()
                .withHeader("Host", "attacker.example.test"));

        assertThat(exchange).isSameAs(rawSocketExchange);
        assertThat(unstreamed).isEmpty();
        assertThat(rawSocket).singleElement().satisfies(request -> {
            assertThat(request.headerValue("Host")).isEqualTo("attacker.example.test");
            assertThat(request.headers()).noneMatch(header -> ScannerSentinels.ALL.contains(header.name()));
        });
    }

    @Test
    void resendsAProbeWhoseHostHeaderNamesItsOwnUrl() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));

        fallback.around(burp).sendRequest(plainProbe().withHeader("Host", "MCP.example.test"));

        assertThat(unstreamed).hasSize(1);
        assertThat(rawSocket).isEmpty();
    }

    @Test
    void stillSendsAProxyRoutedProbeThroughBurpAfterAnUnroutedProbeToTheSameUrlStreamed() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));
        Http wrapped = fallback.around(burp);

        wrapped.sendRequest(plainProbe());
        wrapped.sendRequest(routedProbe());
        wrapped.sendRequest(plainProbe());

        verify(burp, times(2)).sendRequest(any(HttpRequest.class));
        assertThat(unstreamed).hasSize(3);
    }

    @Test
    void sendsEveryLaterProbeStraightOutsideBurpOnceAProxyRoutedProbeToTheUrlStreamed() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));
        Http wrapped = fallback.around(burp);

        wrapped.sendRequest(routedProbe());
        wrapped.sendRequest(plainProbe());
        wrapped.sendRequest(routedProbe());

        verify(burp, times(1)).sendRequest(any(HttpRequest.class));
        assertThat(unstreamed).hasSize(3);
    }

    @Test
    void reportsAProbeResentOutsideBurpToTheHttpBurpRefusedItThrough() {
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException(STREAMED));
        OutsideBurpRecorder observed = new OutsideBurpRecorder(burp);

        fallback.send(observed, directProbe(), options);

        assertThat(observed.reported()).containsExactly(unstreamedExchange);
    }

    @Test
    void reportsEachRefusalAndEachLaterSendStraightOutsideBurpAsRefusedByBurp() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));
        OutsideBurpRecorder observed = new OutsideBurpRecorder(burp);
        Http wrapped = fallback.around(observed);

        wrapped.sendRequest(routedProbe());
        wrapped.sendRequest(routedProbe());

        assertThat(observed.refusals()).isEqualTo(2);
    }

    @Test
    void reportsNoRefusalWhenBurpServesTheProbe() {
        when(burp.sendRequest(any(HttpRequest.class))).thenReturn(unstreamedExchange);
        OutsideBurpRecorder observed = new OutsideBurpRecorder(burp);

        fallback.around(observed).sendRequest(routedProbe());

        assertThat(observed.refusals()).isZero();
    }

    @Test
    void reportsEveryProbeSentStraightOutsideBurpToTheHttpItWraps() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));
        OutsideBurpRecorder observed = new OutsideBurpRecorder(burp);
        Http wrapped = fallback.around(observed);

        wrapped.sendRequest(routedProbe());
        wrapped.sendRequest(routedProbe());

        assertThat(observed.reported()).containsExactly(unstreamedExchange, unstreamedExchange);
    }

    @Test
    void reportsAProbeTheRawSocketClientSent() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));
        OutsideBurpRecorder observed = new OutsideBurpRecorder(burp);

        fallback.around(observed).sendRequest(plainProbe().withHeader("Host", "attacker.example.test"));

        assertThat(observed.reported()).containsExactly(rawSocketExchange);
    }

    @Test
    void reportsNothingForAProbeTheRawSocketClientCouldNotSend() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));
        OutsideBurpRecorder observed = new OutsideBurpRecorder(burp);
        rawSocketConnects = false;

        HttpRequestResponse exchange = fallback.around(observed)
                .sendRequest(plainProbe().withHeader("Host", "attacker.example.test"));

        assertThat(exchange.response()).isNull();
        assertThat(observed.reported()).isEmpty();
    }

    @Test
    void sendsNothingOutsideBurpBeforeBurpRefusesAStream() {
        HttpRequest probe = plainProbe().withHeader("Host", "attacker.example.test");

        assertThat(fallback.sendsOutsideBurp(probe)).isFalse();
    }

    @Test
    void sendsLaterProbesToAStreamingUrlOutsideBurp() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));

        fallback.around(burp).sendRequest(plainProbe());

        assertThat(fallback.sendsOutsideBurp(plainProbe())).isTrue();
    }

    @Test
    void sendsALaterProbeToAStreamingUrlWhoseHostHeaderNamesAnotherHostStraightToTheRawSocketClient() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));
        Http wrapped = fallback.around(burp);

        wrapped.sendRequest(plainProbe());
        wrapped.sendRequest(plainProbe().withHeader("Host", "attacker.example.test"));

        verify(burp, times(1)).sendRequest(any(HttpRequest.class));
        assertThat(unstreamed).hasSize(1);
        assertThat(rawSocket).hasSize(1);
    }

    @Test
    void sendsThroughBurpAgainOnceItForgetsTheStreamedRoutes() {
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));
        fallback.around(burp).sendRequest(routedProbe());

        fallback.forgetStreamedRoutes();

        assertThat(fallback.sendsOutsideBurp(routedProbe())).isFalse();
        assertThat(fallback.sendsOutsideBurp(directProbe())).isFalse();
    }

    @Test
    void forgetsDirectlyStreamingRoutesToo() {
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException(STREAMED));
        fallback.send(burp, directProbe(), options);

        fallback.forgetStreamedRoutes();

        assertThat(fallback.sendsOutsideBurp(directProbe())).isFalse();
    }

    @Test
    void reportsNothingWhileBurpAnswers() {
        when(burp.sendRequest(any(HttpRequest.class))).thenReturn(mock(HttpRequestResponse.class));
        OutsideBurpRecorder observed = new OutsideBurpRecorder(burp);

        fallback.around(observed).sendRequest(routedProbe());

        assertThat(observed.reported()).isEmpty();
    }

    private static HttpRequest plainProbe() {
        return HttpRequest.httpRequestFromUrl(ENDPOINT).withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");
    }

    private static HttpRequest routedProbe() {
        return plainProbe().withHeader(ScannerSentinels.STRIP_AUTH_HEADER, ScannerSentinels.SENTINEL_VALUE);
    }

    private static HttpRequest directProbe() {
        return HttpRequest.httpRequestFromUrl(ENDPOINT).withMethod("POST")
                .withHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER, ScannerSentinels.SENTINEL_VALUE)
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");
    }
}
