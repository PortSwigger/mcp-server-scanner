package com.mcpscanner.auth.oauth.discovery;

import com.mcpscanner.logging.McpEventLog;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuthMetadataDiscovererTest {

    private static final URI MCP_RESOURCE = URI.create("https://mcp.example.com/mcp");
    private static final String FAILURE_MESSAGE = "No OAuth metadata found at any standard path";

    private MetadataProbe probe1;
    private MetadataProbe probe2;
    private MetadataProbe probe3;
    private DiscoveredMetadata metadata;

    @BeforeEach
    void setUp() {
        probe1 = mock(MetadataProbe.class);
        probe2 = mock(MetadataProbe.class);
        probe3 = mock(MetadataProbe.class);
        metadata = new DiscoveredMetadata(URI.create("https://issuer.example"), DiscoverySource.WWW_AUTHENTICATE_HEADER, mock(AuthorizationServerMetadata.class));
    }

    @Test
    void discoverReturnsFirstProbeResultAndSkipsRemaining() throws Exception {
        when(probe1.probe(MCP_RESOURCE)).thenReturn(Optional.of(metadata));

        DiscoveredMetadata result = orchestrator().discover(MCP_RESOURCE);

        assertThat(result).isSameAs(metadata);
        verify(probe2, never()).probe(any());
        verify(probe3, never()).probe(any());
    }

    @Test
    void discoverFallsThroughToSecondProbeWhenFirstEmpty() throws Exception {
        when(probe1.probe(MCP_RESOURCE)).thenReturn(Optional.empty());
        when(probe2.probe(MCP_RESOURCE)).thenReturn(Optional.of(metadata));

        DiscoveredMetadata result = orchestrator().discover(MCP_RESOURCE);

        assertThat(result).isSameAs(metadata);
        verify(probe3, never()).probe(any());
    }

    @Test
    void discoverFallsThroughToThirdProbeWhenFirstTwoEmpty() throws Exception {
        when(probe1.probe(MCP_RESOURCE)).thenReturn(Optional.empty());
        when(probe2.probe(MCP_RESOURCE)).thenReturn(Optional.empty());
        when(probe3.probe(MCP_RESOURCE)).thenReturn(Optional.of(metadata));

        DiscoveredMetadata result = orchestrator().discover(MCP_RESOURCE);

        assertThat(result).isSameAs(metadata);
    }

    @Test
    void discoverThrowsWhenAllProbesEmpty() {
        when(probe1.probe(MCP_RESOURCE)).thenReturn(Optional.empty());
        when(probe2.probe(MCP_RESOURCE)).thenReturn(Optional.empty());
        when(probe3.probe(MCP_RESOURCE)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> orchestrator().discover(MCP_RESOURCE))
                .isInstanceOf(DiscoveryFailedException.class)
                .hasMessage(FAILURE_MESSAGE);
    }

    @Test
    void discoverThrowsWhenProbeListEmpty() {
        OAuthMetadataDiscoverer discoverer = new OAuthMetadataDiscoverer(List.of());

        assertThatThrownBy(() -> discoverer.discover(MCP_RESOURCE))
                .isInstanceOf(DiscoveryFailedException.class)
                .hasMessage(FAILURE_MESSAGE);
    }

    @Test
    void defaultInstanceReturnsNonNull() {
        assertThat(OAuthMetadataDiscoverer.defaultInstance()).isNotNull();
    }

    @Test
    void discoverFailsFastWhenBuiltWithoutHttp() {
        OAuthMetadataDiscoverer discoverer = OAuthMetadataDiscoverer.defaultInstance();

        assertThatThrownBy(() -> discoverer.discover(MCP_RESOURCE))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Http is required");
    }

    @Test
    void logsSummaryLineOnSuccess() throws Exception {
        McpEventLog eventLog = new McpEventLog(null);
        when(probe1.probe(MCP_RESOURCE)).thenReturn(Optional.of(metadata));
        OAuthMetadataDiscoverer discoverer = new OAuthMetadataDiscoverer(List.of(probe1), eventLog);

        discoverer.discover(MCP_RESOURCE);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().contains("OAuth metadata discovered")
                        && entry.message().contains("WWW_AUTHENTICATE_HEADER"));
    }

    @Test
    void logsSummaryLineOnFailure() {
        McpEventLog eventLog = new McpEventLog(null);
        when(probe1.probe(MCP_RESOURCE)).thenReturn(Optional.empty());
        OAuthMetadataDiscoverer discoverer = new OAuthMetadataDiscoverer(List.of(probe1), eventLog);

        assertThatThrownBy(() -> discoverer.discover(MCP_RESOURCE))
                .isInstanceOf(DiscoveryFailedException.class);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("OAuth metadata discovery failed"));
    }

    private OAuthMetadataDiscoverer orchestrator() {
        return new OAuthMetadataDiscoverer(List.of(probe1, probe2, probe3));
    }
}
