package com.mcpscanner.identity.discovery;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.PrincipalListings;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public final class IdentityListings implements PrincipalListings {

    private final Map<String, DiscoveryOutcome> outcomes = new HashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    @Override
    public Optional<Boolean> lists(String principalId, AccessItemKey item) {
        return outcome(principalId)
                .filter(DiscoveryOutcome.Listed.class::isInstance)
                .map(listed -> ((DiscoveryOutcome.Listed) listed).listing().lists(item));
    }

    public List<HttpRequestResponse> toolsListExchanges(String principalId) {
        return outcome(principalId)
                .filter(DiscoveryOutcome.Listed.class::isInstance)
                .map(listed -> ((DiscoveryOutcome.Listed) listed).toolsList())
                .orElse(List.of());
    }

    public synchronized Optional<DiscoveryOutcome> outcome(String principalId) {
        return Optional.ofNullable(outcomes.get(principalId));
    }

    public synchronized Map<String, DiscoveryOutcome> outcomes() {
        return Map.copyOf(outcomes);
    }

    public void addListener(Runnable listener) {
        listeners.add(listener);
    }

    public void removeListener(Runnable listener) {
        listeners.remove(listener);
    }

    void record(String principalId, DiscoveryOutcome outcome) {
        synchronized (this) {
            outcomes.put(principalId, outcome);
        }
        fireChanged();
    }

    void retainOnly(Set<String> principalIds) {
        boolean removed;
        synchronized (this) {
            removed = outcomes.keySet().retainAll(principalIds);
        }
        if (removed) {
            fireChanged();
        }
    }

    void clear() {
        boolean hadOutcomes;
        synchronized (this) {
            hadOutcomes = !outcomes.isEmpty();
            outcomes.clear();
        }
        if (hadOutcomes) {
            fireChanged();
        }
    }

    private void fireChanged() {
        listeners.forEach(Runnable::run);
    }
}
