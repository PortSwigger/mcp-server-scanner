package com.mcpscanner.ui.widgets;

import com.mcpscanner.ui.state.ConnectPhase;
import com.mcpscanner.ui.state.ConnectionStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StatusClusterTest {

    @Test
    void disconnectedShowsGrayDotAndDisconnectedText() {
        StatusCluster cluster = new StatusCluster();

        cluster.update(ConnectionStatus.disconnected());

        assertThat(cluster.statusText()).isEqualTo("Disconnected");
        assertThat(cluster.dotColor()).isEqualTo(StatusCluster.DOT_GRAY);
    }

    @Test
    void connectingShowsAmberDot() {
        StatusCluster cluster = new StatusCluster();

        cluster.update(ConnectionStatus.connecting("Authorizing"));

        assertThat(cluster.dotColor()).isEqualTo(StatusCluster.DOT_AMBER);
        assertThat(cluster.statusText()).contains("Authorizing");
    }

    @Test
    void connectedShowsGreenDot() {
        StatusCluster cluster = new StatusCluster();

        cluster.update(ConnectionStatus.connected("u", "h", 5L, 12));

        assertThat(cluster.dotColor()).isEqualTo(StatusCluster.DOT_GREEN);
    }

    @Test
    void failedShowsRedDotAndIncludesReason() {
        StatusCluster cluster = new StatusCluster();

        cluster.update(ConnectionStatus.failed(ConnectPhase.OAUTH, "bad issuer"));

        assertThat(cluster.dotColor()).isEqualTo(StatusCluster.DOT_RED);
        assertThat(cluster.statusText()).contains("bad issuer");
    }

    @Test
    void labelDisablesHtmlSoServerTextIsNeverRenderedAsMarkup() {
        StatusCluster cluster = new StatusCluster();

        assertThat(cluster.labelHtmlDisabled()).isEqualTo(Boolean.TRUE);
    }

    @Test
    void tooltipEscapesServerControlledHtml() {
        StatusCluster cluster = new StatusCluster();

        cluster.update(ConnectionStatus.failed(ConnectPhase.OAUTH, "<html><b>x &amp; y</b>"));

        assertThat(cluster.tooltipText())
                .doesNotStartWith("<html>")
                .contains("&lt;html&gt;")
                .contains("&lt;b&gt;")
                .contains("&amp;amp;");
    }
}
