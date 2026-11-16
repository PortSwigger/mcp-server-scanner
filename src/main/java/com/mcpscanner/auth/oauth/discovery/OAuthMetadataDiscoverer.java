package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import com.mcpscanner.auth.oauth.safety.DefaultSuspiciousDestinationGate;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

public final class OAuthMetadataDiscoverer {

    private static final String FAILURE_MESSAGE = "No OAuth metadata found at any standard path";

    private final Function<DiscoveryTrail, List<MetadataProbe>> probesForTrail;
    private final McpEventLog eventLog;
    private final Http defaultProbeHttp;
    private final boolean defaultProbeHttpRequired;

    public OAuthMetadataDiscoverer(List<MetadataProbe> probes) {
        this(probes, null);
    }

    public OAuthMetadataDiscoverer(List<MetadataProbe> probes, McpEventLog eventLog) {
        this(fixedProbes(probes), eventLog, null, false);
    }

    private OAuthMetadataDiscoverer(Function<DiscoveryTrail, List<MetadataProbe>> probesForTrail,
                                    McpEventLog eventLog,
                                    Http defaultProbeHttp,
                                    boolean defaultProbeHttpRequired) {
        this.probesForTrail = probesForTrail;
        this.eventLog = eventLog;
        this.defaultProbeHttp = defaultProbeHttp;
        this.defaultProbeHttpRequired = defaultProbeHttpRequired;
    }

    public DiscoveredMetadata discover(URI mcpResource) throws DiscoveryFailedException {
        if (defaultProbeHttpRequired) {
            Objects.requireNonNull(defaultProbeHttp, "Http is required to perform OAuth metadata discovery");
        }
        DiscoveryTrail trail = new DiscoveryTrail();
        for (MetadataProbe probe : probesForTrail.apply(trail)) {
            Optional<DiscoveredMetadata> result = probe.probe(mcpResource);
            if (result.isPresent()) {
                DiscoveredMetadata metadata = trail.applyTo(result.get());
                logSuccess(metadata);
                return metadata;
            }
        }
        logFailure();
        throw new DiscoveryFailedException(FAILURE_MESSAGE);
    }

    private static Function<DiscoveryTrail, List<MetadataProbe>> fixedProbes(List<MetadataProbe> probes) {
        List<MetadataProbe> fixed = List.copyOf(probes);
        return trail -> fixed;
    }

    public AuthRequirement requirementFor(URI mcpResource, ChallengeStrategy strategy) {
        Objects.requireNonNull(defaultProbeHttp, "Http is required to probe the auth requirement");
        return new AuthRequirementProbe(defaultProbeHttp, this, eventLog).probe(mcpResource, strategy);
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

    public static OAuthMetadataDiscoverer defaultInstance() {
        return defaultInstance((Http) null);
    }

    public static OAuthMetadataDiscoverer defaultInstance(Http http) {
        return defaultInstance(http, null);
    }

    public static OAuthMetadataDiscoverer defaultInstance(Http http, McpEventLog eventLog) {
        return defaultInstance(http, eventLog, DefaultSuspiciousDestinationGate.denyingSuspicious(eventLog));
    }

    public static OAuthMetadataDiscoverer defaultInstance(Http http,
                                                          McpEventLog eventLog,
                                                          SuspiciousDestinationGate gate) {
        PrmToAsResolver prmToAsResolver = new PrmToAsResolver(http, eventLog, gate);
        return new OAuthMetadataDiscoverer(trail -> List.of(
                new WwwAuthenticateProbe(http, prmToAsResolver, gate, eventLog, trail),
                new PrmWellKnownProbe(http, prmToAsResolver, gate, eventLog, trail),
                new AsWellKnownProbe(http, gate, eventLog)),
                eventLog, http, true);
    }

}
