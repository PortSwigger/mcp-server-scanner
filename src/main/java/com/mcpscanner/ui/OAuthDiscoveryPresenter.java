package com.mcpscanner.ui;

import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.AuthState;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.ui.state.ConnectionStatus;

import javax.swing.SwingUtilities;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public final class OAuthDiscoveryPresenter {

    public interface View {
        void onDiscoveryInFlight();

        void onDiscoverySuccess(DiscoveredMetadata metadata, List<String> advertisedScopes);

        void onDiscoveryFailure();

        void onDiscoveryInvalidUrl(String detail);
    }

    private final OAuthMetadataDiscoverer discoverer;
    private final Executor workerExecutor;
    private final Executor uiExecutor;
    private final ExecutorService ownedExecutor;

    private volatile boolean inFlight;

    public OAuthDiscoveryPresenter(OAuthMetadataDiscoverer discoverer) {
        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "oauth-discovery-worker");
            t.setDaemon(true);
            return t;
        });
        this.discoverer = discoverer;
        this.workerExecutor = executor;
        this.uiExecutor = SwingUtilities::invokeLater;
        this.ownedExecutor = executor;
    }

    OAuthDiscoveryPresenter(OAuthMetadataDiscoverer discoverer,
                            Executor workerExecutor,
                            Executor uiExecutor) {
        this.discoverer = discoverer;
        this.workerExecutor = workerExecutor;
        this.uiExecutor = uiExecutor;
        this.ownedExecutor = null;
    }

    public void shutdown() {
        if (ownedExecutor == null) {
            return;
        }
        ownedExecutor.shutdownNow();
        try {
            ownedExecutor.awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    ExecutorService ownedExecutorForTest() {
        return ownedExecutor;
    }

    public boolean isDiscoveryInFlight() {
        return inFlight;
    }

    public DiscoveredMetadata discoverSync(URI mcpResource) throws DiscoveryFailedException {
        return discoverer.discover(mcpResource);
    }

    public void discoverMetadata(View view, String endpoint) {
        if (inFlight) {
            return;
        }
        URI mcpResource = parseEndpoint(endpoint);
        if (mcpResource == null) {
            uiExecutor.execute(() -> view.onDiscoveryInvalidUrl(rejectionDetail(endpoint)));
            return;
        }
        inFlight = true;
        uiExecutor.execute(view::onDiscoveryInFlight);
        workerExecutor.execute(() -> runDiscovery(view, mcpResource));
    }

    public ConnectionStatus buildConnectedStatus(OAuthAuthCodeStrategy strategy, String host, int toolCount) {
        if (strategy == null) {
            return ConnectionStatus.connected(null, host, null, toolCount);
        }
        AuthState state = strategy.snapshot();
        if (!state.valid()) {
            return ConnectionStatus.connected(state.subject(), host, null, toolCount);
        }
        long minutes = Math.max(0, Duration.between(Instant.now(), state.expiresAt()).toMinutes());
        return ConnectionStatus.connected(state.subject(), host, minutes, toolCount);
    }

    private void runDiscovery(View view, URI mcpResource) {
        try {
            DiscoveredMetadata metadata = discoverer.discover(mcpResource);
            List<String> advertisedScopes = metadata.advertisedScopes();
            uiExecutor.execute(() -> {
                try {
                    view.onDiscoverySuccess(metadata, advertisedScopes);
                } finally {
                    inFlight = false;
                }
            });
        } catch (Exception ex) {
            uiExecutor.execute(() -> {
                try {
                    view.onDiscoveryFailure();
                } finally {
                    inFlight = false;
                }
            });
        }
    }

    private static URI parseEndpoint(String endpoint) {
        if (endpoint == null || endpoint.trim().isEmpty()) {
            return null;
        }
        try {
            URI uri = URI.create(endpoint.trim());
            if (uri.getScheme() == null || uri.getHost() == null) {
                return null;
            }
            return uri;
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static String rejectionDetail(String endpoint) {
        if (endpoint == null || endpoint.trim().isEmpty()) {
            return "endpoint is empty";
        }
        return "could not parse '" + endpoint.trim() + "'";
    }

}
