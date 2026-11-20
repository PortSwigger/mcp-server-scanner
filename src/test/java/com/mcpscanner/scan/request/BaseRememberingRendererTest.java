package com.mcpscanner.scan.request;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.LaunchedBases;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RawHttpRequestStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BaseRememberingRendererTest {

    private static final String BODY = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\"}";

    private final ScanMessageRenderer delegate = mock(ScanMessageRenderer.class);
    private final LaunchedBases launched = new LaunchedBases();

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void remembersTheBodyOfEveryJsonRpcRequestItRendersAndReturnsItUnchanged() {
        HttpRequest rendered = RawHttpRequestStub.post(BODY, Map.of());
        when(delegate.renderJsonRpc(any(), any(), any())).thenReturn(rendered);

        HttpRequest returned = new BaseRememberingRenderer(delegate, launched)
                .renderJsonRpc("http://mcp.example/mcp", mock(McpMessage.class), Map.of());

        assertThat(returned).isSameAs(rendered);
        assertThat(launched.claimFirstSend(BODY)).isTrue();
    }

    @Test
    void doesNotRememberClientRegistrationsWhichNeverPassThroughTheMcpProxy() {
        HttpRequest rendered = RawHttpRequestStub.post(BODY, Map.of());
        when(delegate.renderClientRegistration(any())).thenReturn(rendered);

        HttpRequest returned = new BaseRememberingRenderer(delegate, launched)
                .renderClientRegistration(mock(ClientRegistrationMessage.class));

        assertThat(returned).isSameAs(rendered);
        assertThat(launched.claimFirstSend(BODY)).isFalse();
    }
}
