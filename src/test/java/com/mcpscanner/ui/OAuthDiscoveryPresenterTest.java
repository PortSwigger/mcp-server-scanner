package com.mcpscanner.ui;

import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.AuthState;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.ui.state.ConnectionState;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.when;

class OAuthDiscoveryPresenterTest {

    private static final URI ENDPOINT = URI.create("https://mcp.example.com/mcp");

    private final RecordingView view = new RecordingView();
    private final SynchronousExecutor inlineExecutor = new SynchronousExecutor();

    @BeforeEach
    void resetView() {
        view.reset();
    }

    @Test
    void inFlightStatusIsPublishedBeforeAsyncWorkStarts() {
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        AtomicBoolean inFlightSeenBeforeDiscover = new AtomicBoolean(false);
        try {
            when(discoverer.discover(ENDPOINT)).thenAnswer(invocation -> {
                inFlightSeenBeforeDiscover.set(view.lastEvent() == DiscoveryEvent.IN_FLIGHT);
                throw new DiscoveryFailedException("ignored");
            });
        } catch (DiscoveryFailedException e) {
            throw new AssertionError(e);
        }
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(discoverer, inlineExecutor, inlineExecutor);

        presenter.discoverMetadata(view, ENDPOINT.toString());

        assertThat(inFlightSeenBeforeDiscover).isTrue();
        assertThat(view.eventsInOrder()).containsSequence(DiscoveryEvent.IN_FLIGHT);
    }

    @Test
    void successPathPublishesSuccessWithMetadata() {
        AuthorizationServerMetadata as = mock(AuthorizationServerMetadata.class);
        when(as.getScopes()).thenReturn(new Scope("read", "write"));
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"), DiscoverySource.AS_WELL_KNOWN, as);
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        try {
            when(discoverer.discover(ENDPOINT)).thenReturn(metadata);
        } catch (DiscoveryFailedException e) {
            throw new AssertionError(e);
        }
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(discoverer, inlineExecutor, inlineExecutor);

        presenter.discoverMetadata(view, ENDPOINT.toString());

        assertThat(view.eventsInOrder())
                .containsSequence(DiscoveryEvent.IN_FLIGHT, DiscoveryEvent.SUCCESS);
        assertThat(view.successMetadata).isSameAs(metadata);
        assertThat(view.successScopes).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    void failurePathPublishesFailure() {
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        try {
            when(discoverer.discover(ENDPOINT)).thenThrow(new DiscoveryFailedException("nope"));
        } catch (DiscoveryFailedException e) {
            throw new AssertionError(e);
        }
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(discoverer, inlineExecutor, inlineExecutor);

        presenter.discoverMetadata(view, ENDPOINT.toString());

        assertThat(view.eventsInOrder())
                .containsSequence(DiscoveryEvent.IN_FLIGHT, DiscoveryEvent.FAILURE);
    }

    @Test
    void invalidUrlPublishesInvalidUrlAndDoesNotCallDiscoverer() throws Exception {
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(discoverer, inlineExecutor, inlineExecutor);

        presenter.discoverMetadata(view, "   ");

        assertThat(view.eventsInOrder()).containsExactly(DiscoveryEvent.INVALID_URL);
    }

    @Test
    void invalidUrlPublishesInvalidUrlForUnparsableEndpoint() {
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(discoverer, inlineExecutor, inlineExecutor);

        presenter.discoverMetadata(view, "not a url");

        assertThat(view.eventsInOrder()).containsExactly(DiscoveryEvent.INVALID_URL);
    }

    @Test
    void uiUpdatesAreMarshalledThroughTheUiExecutor() throws Exception {
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                mock(AuthorizationServerMetadata.class));
        try {
            when(discoverer.discover(ENDPOINT)).thenReturn(metadata);
        } catch (DiscoveryFailedException e) {
            throw new AssertionError(e);
        }
        CountingExecutor uiExecutor = new CountingExecutor();
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(discoverer, inlineExecutor, uiExecutor);

        presenter.discoverMetadata(view, ENDPOINT.toString());

        assertThat(uiExecutor.runCount()).isGreaterThanOrEqualTo(2);
        assertThat(view.eventsInOrder())
                .containsSequence(DiscoveryEvent.IN_FLIGHT, DiscoveryEvent.SUCCESS);
    }

    @Test
    void buildConnectedStatusForOAuthValidStateUsesSubjectAndExpiry() {
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        when(strategy.snapshot()).thenReturn(
                new AuthState("alice", Instant.now().plusSeconds(600), true));
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(
                mock(OAuthMetadataDiscoverer.class), inlineExecutor, inlineExecutor);

        ConnectionStatus status = presenter.buildConnectedStatus(strategy, "mcp.example.com", 3);

        assertThat(status.state()).isEqualTo(ConnectionState.CONNECTED);
        assertThat(status.message()).contains("alice").contains("mcp.example.com").contains("3 tools");
    }

    @Test
    void buildConnectedStatusForOAuthInvalidStateOmitsExpiry() {
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        when(strategy.snapshot()).thenReturn(
                new AuthState("bob", Instant.now().minusSeconds(10), false));
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(
                mock(OAuthMetadataDiscoverer.class), inlineExecutor, inlineExecutor);

        ConnectionStatus status = presenter.buildConnectedStatus(strategy, "mcp.example.com", 1);

        assertThat(status.message()).contains("bob").doesNotContain("expires in");
    }

    @Test
    void buildConnectedStatusForNoOauthStrategyOmitsSubject() {
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(
                mock(OAuthMetadataDiscoverer.class), inlineExecutor, inlineExecutor);

        ConnectionStatus status = presenter.buildConnectedStatus(null, "host.example", 7);

        assertThat(status.state()).isEqualTo(ConnectionState.CONNECTED);
        assertThat(status.message()).contains("Connected to host.example").contains("7 tools");
    }

    @Test
    void uiCallbacksRunOnUiExecutorThread() throws Exception {
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        try {
            when(discoverer.discover(ENDPOINT)).thenThrow(new DiscoveryFailedException("nope"));
        } catch (DiscoveryFailedException e) {
            throw new AssertionError(e);
        }
        DedicatedThreadExecutor uiExecutor = new DedicatedThreadExecutor("test-ui-thread");
        DedicatedThreadExecutor workerExecutor = new DedicatedThreadExecutor("test-worker-thread");
        ThreadCapturingView capturingView = new ThreadCapturingView(uiExecutor.threadName());
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(discoverer, workerExecutor, uiExecutor);

        presenter.discoverMetadata(capturingView, ENDPOINT.toString());
        capturingView.awaitFailure();

        assertThat(capturingView.allOnUiThread()).isTrue();
        uiExecutor.shutdown();
        workerExecutor.shutdown();
    }

    @Test
    void shutdown_terminatesExecutor() {
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(mock(OAuthMetadataDiscoverer.class));

        presenter.shutdown();

        assertThat(presenter.ownedExecutorForTest().isShutdown()).isTrue();
    }

    @Test
    void shutdown_isIdempotent() {
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(mock(OAuthMetadataDiscoverer.class));

        presenter.shutdown();
        presenter.shutdown();

        assertThat(presenter.ownedExecutorForTest().isShutdown()).isTrue();
    }

    @Test
    void inFlightStaysTrueUntilUiCallbackRuns() throws Exception {
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example.com/"),
                DiscoverySource.AS_WELL_KNOWN,
                mock(AuthorizationServerMetadata.class));
        URI issuerEndpoint = URI.create("https://issuer.example.com/");
        try {
            when(discoverer.discover(issuerEndpoint)).thenReturn(metadata);
        } catch (DiscoveryFailedException e) {
            throw new AssertionError(e);
        }
        DeferredExecutor uiExecutor = new DeferredExecutor();
        OAuthDiscoveryPresenter presenter = new OAuthDiscoveryPresenter(discoverer, inlineExecutor, uiExecutor);

        presenter.discoverMetadata(view, issuerEndpoint.toString());

        verify(discoverer, timeout(2000)).discover(issuerEndpoint);
        assertThat(presenter.isDiscoveryInFlight()).isTrue();

        uiExecutor.drain();

        assertThat(presenter.isDiscoveryInFlight()).isFalse();
    }

    private enum DiscoveryEvent { IN_FLIGHT, SUCCESS, FAILURE, INVALID_URL }

    private static final class RecordingView implements OAuthDiscoveryPresenter.View {
        private final List<DiscoveryEvent> events = new ArrayList<>();
        private DiscoveredMetadata successMetadata;
        private List<String> successScopes;

        @Override
        public void onDiscoveryInFlight() {
            events.add(DiscoveryEvent.IN_FLIGHT);
        }

        @Override
        public void onDiscoverySuccess(DiscoveredMetadata metadata, List<String> advertisedScopes) {
            successMetadata = metadata;
            successScopes = advertisedScopes;
            events.add(DiscoveryEvent.SUCCESS);
        }

        @Override
        public void onDiscoveryFailure() {
            events.add(DiscoveryEvent.FAILURE);
        }

        @Override
        public void onDiscoveryInvalidUrl(String detail) {
            events.add(DiscoveryEvent.INVALID_URL);
        }

        DiscoveryEvent lastEvent() {
            return events.isEmpty() ? null : events.get(events.size() - 1);
        }

        List<DiscoveryEvent> eventsInOrder() {
            return List.copyOf(events);
        }

        void reset() {
            events.clear();
            successMetadata = null;
            successScopes = null;
        }
    }

    private static final class ThreadCapturingView implements OAuthDiscoveryPresenter.View {
        private final String expectedThreadName;
        private final CountDownLatch terminalLatch = new CountDownLatch(1);
        private boolean allOnExpected = true;

        ThreadCapturingView(String expectedThreadName) {
            this.expectedThreadName = expectedThreadName;
        }

        @Override
        public void onDiscoveryInFlight() {
            checkThread();
        }

        @Override
        public void onDiscoverySuccess(DiscoveredMetadata metadata, List<String> advertisedScopes) {
            checkThread();
            terminalLatch.countDown();
        }

        @Override
        public void onDiscoveryFailure() {
            checkThread();
            terminalLatch.countDown();
        }

        @Override
        public void onDiscoveryInvalidUrl(String detail) {
            checkThread();
            terminalLatch.countDown();
        }

        private void checkThread() {
            if (!Thread.currentThread().getName().equals(expectedThreadName)) {
                allOnExpected = false;
            }
        }

        boolean allOnUiThread() {
            return allOnExpected;
        }

        void awaitFailure() throws InterruptedException {
            terminalLatch.await(5, TimeUnit.SECONDS);
        }
    }

    private static final class SynchronousExecutor implements Executor {
        @Override
        public void execute(Runnable command) {
            command.run();
        }
    }

    private static final class DeferredExecutor implements Executor {
        private final Deque<Runnable> queue = new ArrayDeque<>();

        @Override
        public void execute(Runnable command) {
            queue.add(command);
        }

        void drain() {
            while (!queue.isEmpty()) {
                queue.poll().run();
            }
        }
    }

    private static final class CountingExecutor implements Executor {
        private int count;

        @Override
        public void execute(Runnable command) {
            count++;
            command.run();
        }

        int runCount() {
            return count;
        }
    }

    private static final class DedicatedThreadExecutor implements Executor, AutoCloseable {
        private final java.util.concurrent.ExecutorService delegate;
        private final String threadName;

        DedicatedThreadExecutor(String threadName) {
            this.threadName = threadName;
            this.delegate = java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, threadName);
                t.setDaemon(true);
                return t;
            });
        }

        String threadName() {
            return threadName;
        }

        @Override
        public void execute(Runnable command) {
            delegate.execute(command);
        }

        void shutdown() {
            delegate.shutdownNow();
        }

        @Override
        public void close() {
            shutdown();
        }
    }
}
