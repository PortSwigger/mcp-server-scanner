package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import com.mcpscanner.auth.oauth.OAuthMetadataConsistencyListener;
import com.mcpscanner.auth.oauth.safety.DefaultSuspiciousDestinationGate;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationConfirmer;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class OAuthMetadataDiscoverer {

    private static final String FAILURE_MESSAGE = "No OAuth metadata found at any standard path";

    private final List<MetadataProbe> probes;
    private final McpEventLog eventLog;
    private final Http defaultProbeHttp;
    private final boolean defaultProbeHttpRequired;

    public OAuthMetadataDiscoverer(List<MetadataProbe> probes) {
        this(probes, null);
    }

    public OAuthMetadataDiscoverer(List<MetadataProbe> probes, McpEventLog eventLog) {
        this(probes, eventLog, null, false);
    }

    private OAuthMetadataDiscoverer(List<MetadataProbe> probes,
                                    McpEventLog eventLog,
                                    Http defaultProbeHttp,
                                    boolean defaultProbeHttpRequired) {
        this.probes = List.copyOf(probes);
        this.eventLog = eventLog;
        this.defaultProbeHttp = defaultProbeHttp;
        this.defaultProbeHttpRequired = defaultProbeHttpRequired;
    }

    public DiscoveredMetadata discover(URI mcpResource) throws DiscoveryFailedException {
        if (defaultProbeHttpRequired) {
            Objects.requireNonNull(defaultProbeHttp, "Http is required to perform OAuth metadata discovery");
        }
        for (MetadataProbe probe : probes) {
            Optional<DiscoveredMetadata> result = probe.probe(mcpResource);
            if (result.isPresent()) {
                DiscoveredMetadata metadata = result.get();
                logSuccess(metadata);
                return metadata;
            }
        }
        logFailure();
        throw new DiscoveryFailedException(FAILURE_MESSAGE);
    }

    private void logSuccess(DiscoveredMetadata metadata) {
        if (eventLog == null) {
            return;
        }
        eventLog.info("OAuth metadata discovered via " + metadata.source().name()
                + " at " + metadata.issuer());
    }

    private void logFailure() {
        if (eventLog == null) {
            return;
        }
        eventLog.warn("OAuth metadata discovery failed - no probes returned metadata");
    }

    /**
     * Construction-only overload for UI wiring that builds a discoverer without an
     * {@link Http} instance available (e.g. the no-arg {@code ServerConfigPanel} constructor).
     * The probes tolerate a {@code null} {@link Http} at construction; only an actual
     * {@code discover(...)} call would fail. Production paths use the {@link Http}-accepting
     * overloads below.
     */
    public static OAuthMetadataDiscoverer defaultInstance() {
        return defaultInstance((Http) null);
    }

    public static OAuthMetadataDiscoverer defaultInstance(Http http) {
        return defaultInstance(http, null);
    }

    public static OAuthMetadataDiscoverer defaultInstance(Http http, McpEventLog eventLog) {
        return defaultInstance(http, eventLog, defaultGate(eventLog));
    }

    /**
     * Builds the default probe chain wired to the supplied gate. Discovery GETs are sent via
     * Burp's {@code api.http()} with {@link DiscoveryRequestOptions#noRedirect()} so they honour
     * Burp's upstream proxy and appear in history, while preserving the prior {@code Redirect.NEVER}
     * SSRF guard — discovery must never follow a redirect out from under the gate.
     */
    public static OAuthMetadataDiscoverer defaultInstance(Http http,
                                                          McpEventLog eventLog,
                                                          SuspiciousDestinationGate gate) {
        return defaultInstance(http, eventLog, gate, OAuthMetadataConsistencyListener.noop());
    }

    public static OAuthMetadataDiscoverer defaultInstance(Http http,
                                                          McpEventLog eventLog,
                                                          SuspiciousDestinationGate gate,
                                                          OAuthMetadataConsistencyListener consistencyListener) {
        PrmToAsResolver prmToAsResolver = new PrmToAsResolver(http, eventLog, gate, consistencyListener);
        return new OAuthMetadataDiscoverer(List.of(
                new WwwAuthenticateProbe(http, prmToAsResolver, gate, eventLog),
                new PrmWellKnownProbe(http, prmToAsResolver, gate, eventLog),
                new AsWellKnownProbe(http, gate, eventLog)),
                eventLog, http, true);
    }

    private static SuspiciousDestinationGate defaultGate(McpEventLog eventLog) {
        return DefaultSuspiciousDestinationGate.withConfirmer(
                SuspiciousDestinationConfirmer.alwaysDeny(), eventLog);
    }
}
