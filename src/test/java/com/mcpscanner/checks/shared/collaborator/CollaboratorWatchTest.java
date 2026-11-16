package com.mcpscanner.checks.shared.collaborator;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionType;
import com.mcpscanner.checks.shared.scancontext.CurrentInvocation;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MutableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CollaboratorWatchTest {

    private static final InteractionWindow WINDOW = new InteractionWindow(Duration.ofSeconds(3), Duration.ofSeconds(1));

    private final MutableClock clock = new MutableClock(Instant.parse("2026-11-11T10:00:00Z"));
    private final FakeCollaborator collaborator = new FakeCollaborator();
    private final ManualTicker ticker = new ManualTicker();
    private final McpEventLog eventLog = mock(McpEventLog.class);
    private final CollaboratorWatch watch = watchOver(collaborator);
    private final List<ObservedInteractions> heard = new ArrayList<>();

    @Test
    void returnsAtOnceAndReportsAnInteractionThatArrivesAfterwards() {
        CollaboratorPayload payload = minted();
        watch.watch(List.of(payload), listening(WatchDecision.DONE));

        collaborator.interact(payload, InteractionType.HTTP);
        assertThat(heard).isEmpty();
        ticker.tick();

        assertThat(heard).singleElement().satisfies(observed -> assertThat(observed.of(payload)).hasSize(1));
        assertThat(watch.watchedCount()).isZero();
    }

    @Test
    void aRegistrationKeepsTheCurrentInvocationsExchangesUntilItResolves() {
        RecordingLease lease = new RecordingLease();
        CollaboratorPayload payload = minted();
        CurrentInvocation.holding(lease, () -> {
            watch.watch(List.of(payload), listening(WatchDecision.DONE));
            return null;
        });
        lease.close();
        assertThat(lease.retentionsReleased()).isZero();

        collaborator.interact(payload, InteractionType.HTTP);
        ticker.tick();

        assertThat(lease.retentionsTaken()).isEqualTo(1);
        assertThat(lease.retentionsReleased()).isEqualTo(1);
    }

    @Test
    void aRegistrationReleasesItsExchangesWhenItExpiresUnanswered() {
        RecordingLease lease = new RecordingLease();
        CurrentInvocation.holding(lease, () -> {
            watch.watch(List.of(minted()), listening(WatchDecision.DONE));
            return null;
        });

        clock.advance(CollaboratorWatch.PENDING_LIFETIME.plusSeconds(1));
        ticker.tick();

        assertThat(lease.retentionsReleased()).isEqualTo(1);
    }

    @Test
    void keepsWatchingAndReportsEveryLaterInteractionWithThoseBefore() {
        CollaboratorPayload payload = minted();
        watch.watch(List.of(payload), listening(WatchDecision.KEEP_WATCHING));
        collaborator.interact(payload, InteractionType.DNS);
        ticker.tick();
        clock.advance(Duration.ofSeconds(1));
        ticker.tick();
        collaborator.interact(payload, InteractionType.HTTP);
        clock.advance(Duration.ofSeconds(1));
        ticker.tick();

        assertThat(heard).extracting(observed -> observed.of(payload).size()).containsExactly(1, 2);
        assertThat(watch.watchedCount()).isEqualTo(1);
    }

    @Test
    void ignoresInteractionsForPayloadsItIsNotWatching() {
        CollaboratorPayload payload = minted();
        watch.watch(List.of(payload), listening(WatchDecision.DONE));
        collaborator.interactWithUnknownPayload("stranger");

        ticker.tick();

        assertThat(heard).isEmpty();
    }

    @Test
    void stopsWatchingAProbeFifteenMinutesAfterItWasSent() {
        CollaboratorPayload payload = minted();
        watch.watch(List.of(payload), listening(WatchDecision.KEEP_WATCHING));
        clock.advance(CollaboratorWatch.PENDING_LIFETIME.plusSeconds(1));
        ticker.tick();
        collaborator.interact(payload, InteractionType.HTTP);
        clock.advance(Duration.ofSeconds(1));
        ticker.tick();

        assertThat(heard).isEmpty();
        assertThat(watch.watchedCount()).isZero();
    }

    @Test
    void dropsTheOldestProbeOnceTheLimitIsReached() {
        CollaboratorPayload oldest = minted();
        watch.watch(List.of(oldest), listening(WatchDecision.KEEP_WATCHING));
        for (int i = 1; i < CollaboratorWatch.MAX_PENDING; i++) {
            watch.watch(List.of(FakeCollaborator.payload("filler" + i)), observed -> WatchDecision.KEEP_WATCHING);
        }
        watch.watch(List.of(minted()), observed -> WatchDecision.KEEP_WATCHING);
        collaborator.interact(oldest, InteractionType.HTTP);

        ticker.tick();

        assertThat(watch.watchedCount()).isEqualTo(CollaboratorWatch.MAX_PENDING);
        assertThat(heard).isEmpty();
    }

    @Test
    void startsOnePollerLazilyOnTheFirstWatchedProbe() {
        assertThat(ticker.starts()).isZero();
        watch.watch(List.of(), listening(WatchDecision.DONE));
        assertThat(ticker.starts()).isZero();

        watch.watch(List.of(minted()), listening(WatchDecision.DONE));
        watch.watch(List.of(minted()), listening(WatchDecision.DONE));

        assertThat(ticker.starts()).isEqualTo(1);
    }

    @Test
    void unloadStopsThePollerAndWatchesNothingAfterwards() {
        watch.watch(List.of(minted()), listening(WatchDecision.DONE));

        watch.shutdown();
        watch.watch(List.of(minted()), listening(WatchDecision.DONE));

        assertThat(ticker.stopped()).isTrue();
        assertThat(ticker.starts()).isEqualTo(1);
        assertThat(watch.watchedCount()).isEqualTo(1);
    }

    @Test
    void pollsNothingOnceNoProbeIsWatched() {
        CollaboratorPayload payload = minted();
        watch.watch(List.of(payload), listening(WatchDecision.DONE));
        collaborator.interact(payload, InteractionType.DNS);
        ticker.tick();
        int afterDelivery = collaborator.pollCount();
        clock.advance(WINDOW.pollInterval());

        ticker.tick();

        assertThat(collaborator.pollCount()).isEqualTo(afterDelivery);
    }

    @Test
    void pollsAtMostOncePerPollInterval() {
        watch.watch(List.of(minted()), listening(WatchDecision.DONE));

        ticker.tick();
        ticker.tick();
        clock.advance(WINDOW.pollInterval());
        ticker.tick();

        assertThat(collaborator.pollCount()).isEqualTo(2);
    }

    @Test
    void isSettledOnlyOnceAPollFollowsTheSettleWindowOfEveryProbe() {
        watch.watch(List.of(minted()), listening(WatchDecision.KEEP_WATCHING));
        ticker.tick();
        boolean beforeWindow = watch.settled();
        clock.advance(WINDOW.settle());
        ticker.tick();

        assertThat(beforeWindow).isFalse();
        assertThat(watch.settled()).isTrue();
        assertThat(watch.watchedCount()).isEqualTo(1);
    }

    @Test
    void awaitSettledPollsUntilTheWindowHasPassedAndDeliversLateInteractions() {
        CollaboratorWatch pacedWatch = new CollaboratorWatch(() -> Optional.of(collaborator), eventLog, ticker,
                new WatchTiming(clock, duration -> {
                    clock.advance(duration);
                    collaborator.interactWithUnknownPayload("noise");
                }, WINDOW));
        CollaboratorPayload payload = pacedWatch.probing(source -> source.newPayload().orElseThrow());
        pacedWatch.watch(List.of(payload), listening(WatchDecision.KEEP_WATCHING));
        collaborator.interact(payload, InteractionType.DNS);
        Instant started = clock.instant();

        pacedWatch.awaitSettled();

        assertThat(pacedWatch.settled()).isTrue();
        assertThat(Duration.between(started, clock.instant())).isEqualTo(WINDOW.settle());
        assertThat(heard).hasSize(1);
    }

    @Test
    void usesTheWindowOfAClientThatDeclaresItsLatency() {
        InteractionWindow local = new InteractionWindow(Duration.ofMillis(600), Duration.ofMillis(200));
        HintedCollaborator hinted = new HintedCollaborator(local);
        CollaboratorWatch hintedWatch = new CollaboratorWatch(() -> Optional.of(hinted), eventLog, ticker,
                new WatchTiming(clock, clock::advance, WINDOW));
        CollaboratorPayload payload = hintedWatch.probing(source -> source.newPayload().orElseThrow());
        hintedWatch.watch(List.of(payload), listening(WatchDecision.KEEP_WATCHING));
        Instant started = clock.instant();

        hintedWatch.awaitSettled();

        assertThat(Duration.between(started, clock.instant())).isEqualTo(local.settle());
    }

    @Test
    void anUnhintedClientIsPolledAtMostOncePerMinuteAcrossTicksAndAwaitSettled() {
        PollRecordingCollaborator real = new PollRecordingCollaborator();
        CollaboratorWatch standardWatch = new CollaboratorWatch(() -> Optional.of(real), eventLog, ticker,
                new WatchTiming(clock, clock::advance, InteractionWindow.standard()));

        for (int second = 0; second < 150; second++) {
            standardWatch.watch(List.of(mintedBy(standardWatch)),
                    listening(WatchDecision.KEEP_WATCHING));
            ticker.tick();
            clock.advance(Duration.ofSeconds(1));
        }
        standardWatch.watch(List.of(mintedBy(standardWatch)),
                listening(WatchDecision.KEEP_WATCHING));
        standardWatch.awaitSettled();
        standardWatch.awaitSettled();
        ticker.tick();

        assertThat(standardWatch.settled()).isTrue();
        assertThat(real.polledAt()).hasSizeGreaterThanOrEqualTo(3);
        for (int poll = 1; poll < real.polledAt().size(); poll++) {
            assertThat(Duration.between(real.polledAt().get(poll - 1), real.polledAt().get(poll)))
                    .isGreaterThanOrEqualTo(Duration.ofSeconds(60));
        }
    }

    @Test
    void awaitSettledJustAfterAPollWaitsForTheNextPollAMinuteLater() {
        CollaboratorWatch standardWatch = new CollaboratorWatch(() -> Optional.of(collaborator), eventLog, ticker,
                new WatchTiming(clock, clock::advance, InteractionWindow.standard()));
        standardWatch.watch(List.of(mintedBy(standardWatch)),
                listening(WatchDecision.KEEP_WATCHING));
        ticker.tick();
        standardWatch.watch(List.of(mintedBy(standardWatch)),
                listening(WatchDecision.KEEP_WATCHING));
        Instant started = clock.instant();

        standardWatch.awaitSettled();

        assertThat(standardWatch.settled()).isTrue();
        assertThat(Duration.between(started, clock.instant())).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    void awaitSettledNeverPausesForANegativeTimeWhenTheDeadlinePassesMidLoop() {
        List<Duration> pauses = new ArrayList<>();
        for (long creepMillis = 1; creepMillis < 4_000; creepMillis += 13) {
            awaitSettledWhileProbesKeepArriving(new CreepingClock(clock, Duration.ofMillis(creepMillis)), pauses);
        }

        assertThat(pauses).isNotEmpty().allSatisfy(pause -> assertThat(pause).isPositive());
    }

    private void awaitSettledWhileProbesKeepArriving(java.time.Clock creeping, List<Duration> pauses) {
        List<CollaboratorWatch> holder = new ArrayList<>();
        CollaboratorWatch unsettling = new CollaboratorWatch(() -> Optional.of(collaborator), eventLog, ticker,
                new WatchTiming(creeping, duration -> {
                    pauses.add(duration);
                    clock.advance(duration);
                    holder.get(0).watch(List.of(mintedBy(holder.get(0))), listening(WatchDecision.KEEP_WATCHING));
                }, InteractionWindow.standard()));
        holder.add(unsettling);
        unsettling.watch(List.of(mintedBy(unsettling)), listening(WatchDecision.KEEP_WATCHING));
        unsettling.awaitSettled();
    }

    @Test
    void awaitSettledReturnsAtOnceWhenNothingIsWatched() {
        Instant started = clock.instant();

        watch.awaitSettled();

        assertThat(clock.instant()).isEqualTo(started);
    }

    @Test
    void logsAndDropsAProbeWhoseReportFails() {
        CollaboratorPayload payload = minted();
        watch.watch(List.of(payload), observed -> {
            throw new IllegalStateException("site map gone");
        });
        collaborator.interact(payload, InteractionType.HTTP);

        ticker.tick();

        verify(eventLog).warn(contains("site map gone"));
        assertThat(watch.watchedCount()).isZero();
    }

    @Test
    void logsAFailedPollWithItsStackTraceAndKeepsTicking() {
        RuntimeException failure = new IllegalStateException("malformed interaction");
        FakeCollaborator failingOnce = new FakeCollaborator() {
            private boolean failed;

            @Override
            public synchronized List<Interaction> getAllInteractions() {
                if (failed) {
                    return super.getAllInteractions();
                }
                failed = true;
                Interaction broken = mock(Interaction.class);
                when(broken.id()).thenThrow(failure);
                return List.of(broken);
            }
        };
        CollaboratorWatch failingWatch = watchOver(failingOnce);
        CollaboratorPayload payload = failingWatch.probing(source -> source.newPayload().orElseThrow());
        failingWatch.watch(List.of(payload), listening(WatchDecision.DONE));

        ticker.tick();
        failingOnce.interact(payload, InteractionType.HTTP);
        clock.advance(Duration.ofSeconds(1));
        ticker.tick();

        verify(eventLog).error(contains("Collaborator watch"), eq(failure));
        assertThat(heard).singleElement().satisfies(observed -> assertThat(observed.of(payload)).hasSize(1));
    }

    @Test
    void mintsNothingWithoutCollaborator() {
        CollaboratorWatch unavailable = watchOver(null);

        assertThat(unavailable.available()).isFalse();
        Optional<CollaboratorPayload> payload = unavailable.probing(source -> source.newPayload());
        assertThat(payload).isEmpty();
    }

    private CollaboratorWatch watchOver(FakeCollaborator client) {
        return new CollaboratorWatch(() -> Optional.ofNullable(client), eventLog, ticker,
                new WatchTiming(clock, clock::advance, WINDOW));
    }

    private CollaboratorPayload minted() {
        return mintedBy(watch);
    }

    private static CollaboratorPayload mintedBy(CollaboratorWatch minter) {
        return minter.probing(source -> source.newPayload().orElseThrow());
    }

    private InteractionListener listening(WatchDecision decision) {
        return observed -> {
            heard.add(observed);
            return decision;
        };
    }

    private static final class CreepingClock extends java.time.Clock {

        private final MutableClock base;
        private final Duration perRead;

        CreepingClock(MutableClock base, Duration perRead) {
            this.base = base;
            this.perRead = perRead;
        }

        @Override
        public java.time.ZoneId getZone() {
            return base.getZone();
        }

        @Override
        public java.time.Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            base.advance(perRead);
            return base.instant();
        }
    }

    private final class PollRecordingCollaborator extends FakeCollaborator {

        private final List<Instant> polledAt = new ArrayList<>();

        @Override
        public synchronized List<Interaction> getAllInteractions() {
            polledAt.add(clock.instant());
            return super.getAllInteractions();
        }

        synchronized List<Instant> polledAt() {
            return List.copyOf(polledAt);
        }
    }

    private static final class RecordingLease implements com.mcpscanner.http.ExchangeLease {

        private int taken;
        private int released;

        @Override
        public void hold(burp.api.montoya.http.message.HttpRequestResponse proxied) {
        }

        @Override
        public com.mcpscanner.http.ExchangeRetention retainBeyondClose() {
            taken++;
            return () -> released++;
        }

        @Override
        public void close() {
        }

        int retentionsTaken() {
            return taken;
        }

        int retentionsReleased() {
            return released;
        }
    }
}
