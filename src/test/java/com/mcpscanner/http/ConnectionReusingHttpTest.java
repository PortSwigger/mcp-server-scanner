package com.mcpscanner.http;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.BurpEmptyResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRequestOptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConnectionReusingHttpTest {

    private static final String MCP_URL = "https://mcp.example.com/mcp";

    private final Http delegate = mock(Http.class);
    private ConnectionReuse reuse;
    private Http http;
    private HttpRequestResponse http1Reply;
    private HttpRequestResponse http2Reply;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        http1Reply = answeredWith("HTTP/1.1");
        http2Reply = answeredWith("HTTP/2");
        reuse = ConnectionReuse.withoutLocalAnswers();
        http = ConnectionReusingHttp.around(delegate, reuse);
    }

    @Test
    void sendsToAnUnknownOriginOnAFreshClosingConnection() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);

        http.sendRequest(request());

        assertThat(plainSends().get(0).headerValue("Connection")).isEqualTo("close");
    }

    @Test
    void reusesOneSharedHttp1ConnectionOnceTheOriginAnsweredHttp1() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString()))
                .thenReturn(http1Reply);

        http.sendRequest(request());
        http.sendRequest(request());

        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        String connectionId = ConnectionReuse.connectionIdFor(request().httpService());
        verify(delegate).sendRequest(sent.capture(), eq(HttpMode.HTTP_1), eq(connectionId));
        assertThat(sent.getValue().hasHeader("Connection")).isFalse();
    }

    @Test
    void neverReusesOneOriginsConnectionIdForAnotherOrigin() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString()))
                .thenReturn(http1Reply);
        HttpRequest previous = HttpRequest.httpRequestFromUrl("http://localhost:8651/mcp");
        HttpRequest current = HttpRequest.httpRequestFromUrl("http://127.0.0.1:8652/mcp");

        http.sendRequest(previous);
        http.sendRequest(previous);
        http.sendRequest(current);
        http.sendRequest(current);

        ArgumentCaptor<String> connectionIds = ArgumentCaptor.forClass(String.class);
        verify(delegate, times(2)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), connectionIds.capture());
        assertThat(connectionIds.getAllValues()).doesNotHaveDuplicates();
    }

    @Test
    void keepsAutoModeWithoutOurConnectionCloseOnceTheOriginAnsweredHttp2() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http2Reply);

        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(plainSends()).extracting(sent -> sent.hasHeader("Connection")).containsExactly(true, false);
        verify(delegate, never()).sendRequest(any(HttpRequest.class), any(HttpMode.class), anyString());
    }

    @Test
    void neverResendsAReusedRequestThatGotNoResponseAndClosesLaterSends() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenReturn(null);

        http.sendRequest(request());
        assertThat(http.sendRequest(request())).isNull();
        http.sendRequest(request());

        verify(delegate, times(1)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString());
        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void treatsAnEmptyReplyOnAReusedConnectionAsNoResponseAndClosesLaterSends() {
        HttpRequestResponse empty = HttpRequestResponse.httpRequestResponse(request(), BurpEmptyResponse.create());
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenReturn(empty);

        http.sendRequest(request());
        assertThat(http.sendRequest(request())).isSameAs(empty);
        http.sendRequest(request());

        verify(delegate, times(1)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString());
        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void learnsNothingFromAnEmptyReply() {
        HttpRequestResponse empty = HttpRequestResponse.httpRequestResponse(request(), BurpEmptyResponse.create());
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(empty);

        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(plainSends()).hasSize(2);
    }

    @Test
    void closesLaterSendsWhenAReusedSendThrows() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString()))
                .thenThrow(new IllegalStateException("Connection reset"));

        http.sendRequest(request());
        assertThatThrownBy(() -> http.sendRequest(request())).hasMessage("Connection reset");
        http.sendRequest(request());

        verify(delegate, times(1)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString());
        assertThat(plainSends()).hasSize(2);
    }

    @Test
    void learnsNothingFromAnUnansweredSend() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(null);

        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(plainSends()).hasSize(2);
    }

    @Test
    void forgetsEveryOriginOnDisconnect() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);

        http.sendRequest(request());
        reuse.forgetOrigins();
        http.sendRequest(request());

        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void remembersEachOriginSeparately() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);

        http.sendRequest(request());
        http.sendRequest(HttpRequest.httpRequestFromUrl("https://mcp.example.com:8443/mcp"));

        assertThat(plainSends()).hasSize(2);
    }

    @Test
    void neitherLearnsFromNorReusesARequestTheLocalProxyAnswers() {
        Http proxied = ConnectionReusingHttp.around(delegate, new ConnectionReuse(request -> true));
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);

        proxied.sendRequest(request());
        proxied.sendRequest(request());

        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void keepsAConnectionHeaderTheCallerChoseWhenReusing() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString()))
                .thenReturn(http1Reply);

        http.sendRequest(request());
        http.sendRequest(request().withHeader("Connection", "Upgrade"));

        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(delegate).sendRequest(sent.capture(), eq(HttpMode.HTTP_1), anyString());
        assertThat(sent.getValue().headerValue("Connection")).isEqualTo("Upgrade");
    }

    @Test
    void addsTheSharedConnectionToTheCallersRequestOptions() {
        ArgumentCaptor<RequestOptions> options = ArgumentCaptor.forClass(RequestOptions.class);
        when(delegate.sendRequest(any(HttpRequest.class), options.capture())).thenReturn(http1Reply);
        RequestOptions noRedirects = RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER);

        http.sendRequest(request(), noRedirects);
        http.sendRequest(request(), noRedirects);

        RecordingRequestOptions fresh = RecordingRequestOptions.recorded(options.getAllValues().get(0));
        RecordingRequestOptions reused = RecordingRequestOptions.recorded(options.getAllValues().get(1));
        assertThat(fresh.httpMode()).isEmpty();
        assertThat(reused.httpMode()).contains(HttpMode.HTTP_1);
        assertThat(reused.connectionId()).contains(ConnectionReuse.connectionIdFor(request().httpService()));
        assertThat(reused.redirectionMode()).contains(RedirectionMode.NEVER);
    }

    @Test
    void keepsAnExplicitHttpModeOnAFreshClosingConnection() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        http.sendRequest(request());

        http.sendRequest(request(), HttpMode.HTTP_2);

        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(delegate).sendRequest(sent.capture(), eq(HttpMode.HTTP_2));
        assertThat(sent.getValue().headerValue("Connection")).isEqualTo("close");
    }

    @Test
    void sendsAnExplicitNamedConnectionUntouched() {
        HttpRequest keepAlive = request().withAddedHeader("Connection", "keep-alive");

        http.sendRequest(keepAlive, HttpMode.AUTO, "caller-connection");

        verify(delegate).sendRequest(keepAlive, HttpMode.AUTO, "caller-connection");
    }

    @Test
    void wrapsOnlyOnce() {
        assertThat(ConnectionReusingHttp.around(http, ConnectionReuse.withoutLocalAnswers())).isSameAs(http);
    }

    private List<HttpRequest> plainSends() {
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(delegate, org.mockito.Mockito.atLeast(0)).sendRequest(sent.capture());
        return sent.getAllValues();
    }

    private static HttpRequest request() {
        return HttpRequest.httpRequestFromUrl(MCP_URL);
    }

    private static HttpRequestResponse answeredWith(String httpVersion) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.httpVersion()).thenReturn(httpVersion);
        when(response.statusCode()).thenReturn((short) 200);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(exchange.response()).thenReturn(response);
        return exchange;
    }
}
