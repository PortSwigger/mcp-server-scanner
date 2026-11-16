package com.mcpscanner.checks.shared.collaborator;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.CollaboratorServer;
import burp.api.montoya.collaborator.Interaction;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.stream.Collectors;

final class CollaboratorInteractions {

    private final Supplier<Optional<CollaboratorClient>> clients;
    private final Set<String> awaited = ConcurrentHashMap.newKeySet();
    private final List<Interaction> received = new ArrayList<>();
    private final Object pollLock = new Object();
    private final SingleFlightPoll polls;
    private Optional<CollaboratorClient> client;

    public CollaboratorInteractions(Supplier<Optional<CollaboratorClient>> clients) {
        this(clients, System::nanoTime);
    }

    public CollaboratorInteractions(Supplier<Optional<CollaboratorClient>> clients, LongSupplier nanoClock) {
        this.clients = Objects.requireNonNull(clients, "clients must not be null");
        this.polls = new SingleFlightPoll(nanoClock);
    }

    public boolean available() {
        return client().isPresent();
    }

    public Optional<CollaboratorPayload> newPayload() {
        return client().flatMap(CollaboratorInteractions::generate).map(this::register);
    }

    public <T> T probing(CollaboratorProbes<T> probes) {
        List<CollaboratorPayload> minted = new ArrayList<>();
        try {
            return probes.send(() -> newPayload().map(payload -> {
                minted.add(payload);
                return payload;
            }));
        } catch (RuntimeException | Error failure) {
            forget(minted);
            throw failure;
        }
    }

    public Optional<CollaboratorServer> server() {
        return client().flatMap(CollaboratorInteractions::serverOf);
    }

    public Optional<InteractionWindow> declaredWindow() {
        return client().filter(InteractionWindowHint.class::isInstance)
                .map(active -> ((InteractionWindowHint) active).interactionWindow());
    }

    public boolean pollIfDue(Duration minimumInterval) {
        return client().map(active -> pollIfDue(active, minimumInterval)).orElse(false);
    }

    public Duration untilPollDue(Duration minimumInterval) {
        return polls.untilDue(minimumInterval);
    }

    public ObservedInteractions received(Collection<CollaboratorPayload> payloads) {
        Set<String> ids = idsOf(payloads);
        synchronized (pollLock) {
            return new ObservedInteractions(received.stream().filter(interaction -> ids.contains(idOf(interaction)))
                    .toList());
        }
    }

    public void forget(Collection<CollaboratorPayload> payloads) {
        Set<String> ids = idsOf(payloads);
        synchronized (pollLock) {
            awaited.removeAll(ids);
            received.removeIf(interaction -> ids.contains(idOf(interaction)));
        }
    }

    private CollaboratorPayload register(CollaboratorPayload payload) {
        awaited.add(payload.id().toString());
        return payload;
    }

    private boolean pollIfDue(CollaboratorClient active, Duration minimumInterval) {
        if (!polls.claimIfDue(minimumInterval)) {
            return false;
        }
        try {
            deliver(poll(active));
            return true;
        } finally {
            polls.release();
        }
    }

    private void deliver(List<Interaction> interactions) {
        synchronized (pollLock) {
            interactions.forEach(this::keepIfAwaited);
        }
    }

    private void keepIfAwaited(Interaction interaction) {
        if (interaction.id() != null && awaited.contains(idOf(interaction)) && isNew(interaction)) {
            received.add(interaction);
        }
    }

    private boolean isNew(Interaction interaction) {
        return received.stream().noneMatch(earlier -> sameEvent(earlier, interaction));
    }

    private static boolean sameEvent(Interaction first, Interaction second) {
        return first == second || (idOf(first).equals(idOf(second))
                && first.type() == second.type()
                && first.clientPort() == second.clientPort()
                && Objects.equals(first.timeStamp(), second.timeStamp())
                && Objects.equals(first.clientIp(), second.clientIp()));
    }

    private static String idOf(Interaction interaction) {
        return interaction.id().toString();
    }

    private static Set<String> idsOf(Collection<CollaboratorPayload> payloads) {
        return payloads.stream().map(payload -> payload.id().toString()).collect(Collectors.toSet());
    }

    private static Optional<CollaboratorPayload> generate(CollaboratorClient active) {
        try {
            return Optional.ofNullable(active.generatePayload());
        } catch (RuntimeException unavailable) {
            return Optional.empty();
        }
    }

    private static Optional<CollaboratorServer> serverOf(CollaboratorClient active) {
        try {
            return Optional.ofNullable(active.server());
        } catch (RuntimeException unavailable) {
            return Optional.empty();
        }
    }

    private static List<Interaction> poll(CollaboratorClient active) {
        try {
            List<Interaction> interactions = active.getAllInteractions();
            return interactions == null ? List.of() : interactions;
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    private synchronized Optional<CollaboratorClient> client() {
        if (client == null || client.isEmpty()) {
            client = supplied();
        }
        return client;
    }

    private Optional<CollaboratorClient> supplied() {
        try {
            return clients.get();
        } catch (RuntimeException unavailable) {
            return Optional.empty();
        }
    }
}
