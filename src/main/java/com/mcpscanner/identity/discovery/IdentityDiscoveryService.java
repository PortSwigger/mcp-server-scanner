package com.mcpscanner.identity.discovery;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.checks.api.crossidentity.SyntheticPrincipals;
import com.mcpscanner.client.RecordedCatalog;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.PrimaryConnection;
import com.mcpscanner.identity.FailureReason;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.logging.McpEventLog;

import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.function.Function;
import java.util.function.Supplier;

public final class IdentityDiscoveryService implements ComparedDiscovery, PreComparisonDiscovery {

    private static final Duration DISCOVERY_LIMIT = Duration.ofSeconds(60);

    private final IdentityRegistry registry;
    private final Function<McpServerConfig, RecordedCatalog> discoverer;
    private final Supplier<List<Principal>> synthetic;
    private final IdentityListings listings;
    private final Executor executor;
    private final McpEventLog eventLog;
    private final SettledListings settled;
    private final Map<String, AuthStrategy> discoveredWith = new HashMap<>();
    private final Set<String> syntheticIds = new HashSet<>();
    private Optional<PrimaryConnection> target = Optional.empty();
    private long generation;

    public IdentityDiscoveryService(IdentityRegistry registry, Function<McpServerConfig, ConnectResult> discoverer,
                                    IdentityListings listings, Executor executor, McpEventLog eventLog) {
        this(registry, config -> RecordedCatalog.unrecorded(discoverer.apply(config)), listings, executor, eventLog,
                List::of);
    }

    public IdentityDiscoveryService(IdentityRegistry registry, Function<McpServerConfig, RecordedCatalog> discoverer,
                                    IdentityListings listings, Executor executor, McpEventLog eventLog,
                                    SyntheticPrincipals synthetic) {
        this(registry, discoverer, listings, executor, eventLog, synthetic::renewed);
    }

    private IdentityDiscoveryService(IdentityRegistry registry, Function<McpServerConfig, RecordedCatalog> discoverer,
                                     IdentityListings listings, Executor executor, McpEventLog eventLog,
                                     Supplier<List<Principal>> synthetic) {
        this.registry = Objects.requireNonNull(registry, "registry");
        this.discoverer = Objects.requireNonNull(discoverer, "discoverer");
        this.synthetic = Objects.requireNonNull(synthetic, "synthetic");
        this.listings = Objects.requireNonNull(listings, "listings");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.eventLog = Objects.requireNonNull(eventLog, "eventLog");
        this.settled = new SettledListings(listings, DISCOVERY_LIMIT);
    }

    public void start() {
        registry.addListener(this::onRegistryChanged);
    }

    public IdentityListings listings() {
        return listings;
    }

    public synchronized void onPrimaryConnected(PrimaryConnection connection) {
        resetFor(Optional.of(connection));
        listings.record(Principal.PRIMARY_ID,
                new DiscoveryOutcome.Listed(IdentityListing.of(connection.catalog()), connection.toolsList()));
        registry.compared().forEach(this::discover);
    }

    public synchronized void onDisconnected() {
        resetFor(Optional.empty());
    }

    public synchronized void refreshAll() {
        if (target.isPresent()) {
            discoveredWith.clear();
            registry.compared().forEach(this::discover);
        }
    }

    @Override
    public synchronized void discover(String identityId) {
        if (target.isPresent()) {
            registry.compared().stream().filter(identity -> identity.id().equals(identityId))
                    .forEach(this::discover);
        }
    }

    @Override
    public void discoverMissing() {
        startDiscoveringMissing();
        awaitSettled(comparedIds());
    }

    @Override
    public PreComparisonDiscovery withSyntheticListings() {
        return () -> {
            startDiscoveringMissing();
            Set<String> listedAsSynthetic = startListingAsSynthetic();
            awaitSettled(union(comparedIds(), listedAsSynthetic));
        };
    }

    public List<HttpRequestResponse> toolsListExchanges(String principalId) {
        return listings.toolsListExchanges(principalId);
    }

    private RecordedCatalog recordedAs(AuthStrategy credential, PrimaryConnection connection) {
        return discoverer.apply(new McpServerConfig(connection.endpoint(), connection.transport(), credential));
    }

    private synchronized Set<String> comparedIds() {
        if (target.isEmpty()) {
            return Set.of();
        }
        Set<String> ids = new HashSet<>();
        registry.compared().forEach(identity -> ids.add(identity.id()));
        return ids;
    }

    private static Set<String> union(Set<String> first, Set<String> second) {
        Set<String> ids = new HashSet<>(first);
        ids.addAll(second);
        return ids;
    }

    private synchronized Set<String> startListingAsSynthetic() {
        if (target.isEmpty()) {
            return Set.of();
        }
        synthetic.get().forEach(principal -> {
            syntheticIds.add(principal.id());
            discover(principal.id(), principal.name(), new CustomHeaderAuthStrategy(principal.credentialHeaders().get()));
        });
        return Set.copyOf(syntheticIds);
    }

    @Override
    public synchronized boolean credentialChangedSinceDiscovery(String identityId) {
        return discoveredWith.containsKey(identityId)
                && registry.credential(identityId).orElse(null) != discoveredWith.get(identityId);
    }

    private synchronized void startDiscoveringMissing() {
        List<Identity> missing = target.isEmpty() ? List.of() : registry.compared().stream()
                .filter(identity -> registry.credential(identity.id()).isPresent())
                .filter(identity -> listings.outcome(identity.id()).isEmpty()).toList();
        missing.forEach(identity -> {
            eventLog.info("Discovering " + identity.name() + " before comparing");
            discover(identity);
        });
    }

    private void awaitSettled(Set<String> comparedIds) {
        if (comparedIds.isEmpty()) {
            return;
        }
        try {
            settled.await(comparedIds::contains);
        } catch (IllegalStateException unsettled) {
            eventLog.warn("Comparing without waiting for discovery: " + unsettled.getMessage());
        }
    }

    private synchronized void onRegistryChanged() {
        if (target.isPresent()) {
            forgetIdentitiesNoLongerCompared(registry.otherUsers().stream().filter(Identity::compared).toList());
        }
    }

    private void resetFor(Optional<PrimaryConnection> connection) {
        generation++;
        target = connection;
        discoveredWith.clear();
        syntheticIds.clear();
        listings.clear();
    }

    private void forgetIdentitiesNoLongerCompared(List<Identity> compared) {
        Set<String> kept = new HashSet<>();
        kept.add(Principal.PRIMARY_ID);
        kept.addAll(syntheticIds);
        compared.forEach(identity -> kept.add(identity.id()));
        discoveredWith.keySet().retainAll(kept);
        listings.retainOnly(kept);
    }

    private void discover(Identity identity) {
        registry.credential(identity.id())
                .ifPresent(credential -> discover(identity.id(), identity.name(), credential));
    }

    private void discover(String id, String name, AuthStrategy credential) {
        PrimaryConnection connection = target.orElseThrow();
        long attempt = generation;
        discoveredWith.put(id, credential);
        listings.record(id, DiscoveryOutcome.Discovering.INSTANCE);
        executor.execute(() -> publish(id, credential, attempt, discoverAs(name, credential, connection)));
    }

    private DiscoveryOutcome discoverAs(String name, AuthStrategy credential, PrimaryConnection connection) {
        try {
            RecordedCatalog recorded = recordedAs(credential, connection);
            IdentityListing listing = IdentityListing.of(recorded.catalog());
            eventLog.info("Identity \"" + name + "\" lists " + listing.toolNames().size() + " tools and "
                    + listing.resourceUris().size() + " resources");
            return new DiscoveryOutcome.Listed(listing, recorded.toolsList());
        } catch (RuntimeException failure) {
            String reason = FailureReason.of(failure);
            eventLog.warn("Identity \"" + name + "\" discovery failed: " + reason);
            return new DiscoveryOutcome.Failed(reason);
        }
    }

    private synchronized void publish(String id, AuthStrategy credential, long attempt, DiscoveryOutcome outcome) {
        if (attempt == generation && discoveredWith.get(id) == credential) {
            listings.record(id, outcome);
        }
    }
}
