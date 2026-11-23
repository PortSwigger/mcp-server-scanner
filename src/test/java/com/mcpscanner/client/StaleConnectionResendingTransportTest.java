package com.mcpscanner.client;

import com.mcpscanner.mcp.ResendableRequests;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class StaleConnectionResendingTransportTest {

    private static final URI MCP = URI.create("http://127.0.0.1:1/mcp");
    private static final Duration TIMEOUT = Duration.ofSeconds(1);

    private final ProtocolHttpTransport delegate = mock(ProtocolHttpTransport.class);
    private final ProtocolHttpTransport transport =
            StaleConnectionResendingTransport.whenResendable(delegate, new ResendableRequests());

    @ParameterizedTest
    @ValueSource(strings = {"DELETE", "POST", "PUT", "PATCH"})
    void aBodylessRequestThatMayWriteIsNeverResent(String httpMethod) throws Exception {
        ProtocolHttpRequest request = bodyless(httpMethod);
        doThrow(new IOException("header parser received no bytes")).when(delegate).send(any(), any());

        assertThatThrownBy(() -> transport.send(request, TIMEOUT)).hasMessageContaining("no bytes");
        verify(delegate, times(1)).send(request, TIMEOUT);
    }

    @Test
    void aBodylessGetIsResentOnce() throws Exception {
        ProtocolHttpRequest request = bodyless("GET");
        ProtocolHttpResponse answered = new ProtocolHttpResponse(200, Map.of(), InputStream.nullInputStream(), MCP);
        doThrow(new IOException("header parser received no bytes")).doReturn(answered)
                .when(delegate).send(any(), any());

        assertThat(transport.send(request, TIMEOUT)).isSameAs(answered);
        verify(delegate, times(2)).send(request, TIMEOUT);
    }

    private static ProtocolHttpRequest bodyless(String httpMethod) {
        return new ProtocolHttpRequest(MCP, httpMethod, Map.of(), null);
    }
}
