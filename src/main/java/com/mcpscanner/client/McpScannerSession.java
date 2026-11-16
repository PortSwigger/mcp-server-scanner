package com.mcpscanner.client;

import com.mcpscanner.mcp.LegacySseRoutes;
import burp.api.montoya.http.HttpService;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.HttpOrigin;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpOperationFraming;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.ResendableRequests;
import com.mcpscanner.mcp.ServerPings;
import com.mcpscanner.mcp.SseProbeStreams;
import com.mcpscanner.core.connection.ConnectionAuthException;
import com.mcpscanner.core.connection.CredentialProvider;
import com.mcpscanner.core.connection.HttpSession;
import com.mcpscanner.core.connection.OperationRecovery;
import com.mcpscanner.core.connection.SseSession;
import com.mcpscanner.core.protocol.ClientProfile;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.core.protocol.McpResponses;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.IntSupplier;
import java.util.function.LongFunction;
import java.util.function.Supplier;

public class McpScannerSession implements ConnectedEndpoint, McpOperationFraming.Framer {

    private static final String LOOPBACK = "127.0.0.1";
    static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(60);
    private static final long INITIALIZE_REQUEST_ID = 1L;
    private static final long FIRST_SCAN_REQUEST_ID = INITIALIZE_REQUEST_ID + 1L;
    static final String SSE_TLS_HINT = "SSE connections don't use Burp's network settings, so a client TLS "
            + "certificate configured in Burp isn't presented. If this server requires one, connect with Streamable "
            + "HTTP or modern HTTP, which do use Burp's settings.";
    static final String SSE_FALLBACK_TLS_HINT = "The HTTP attempt, which uses Burp's settings including any client "
            + "TLS certificate, also failed (see the connection error). The SSE fallback can't present a Burp client "
            + "certificate.";
    static final String SSE_TLS_HINT_BURP_NETWORKING_OFF = "SSE connections don't use Burp's network settings, so a "
            + "client TLS certificate configured in Burp isn't presented. If this server requires one, turn on \""
            + BurpNetworkingSetting.NAME + "\" and connect with Streamable HTTP or modern HTTP.";
    static final String SSE_FALLBACK_TLS_HINT_BURP_NETWORKING_OFF = "The HTTP attempt also failed (see the "
            + "connection error). It went directly because \"" + BurpNetworkingSetting.NAME + "\" is off, so no Burp "
            + "client TLS certificate was presented, and the SSE fallback can't present one either. If this server requires "
            + "one, turn on \"" + BurpNetworkingSetting.NAME + "\" and connect with Streamable HTTP or modern HTTP.";

    private final ClientIdentityProvider identityProvider;
    private final McpEventLog eventLog;
    private final RedirectPolicy redirectPolicy;
    private final ConnectionPreconditions preconditions;
    private final ResendableRequests resendableRequests = new ResendableRequests();
    private final StreamableSessionTerminator sessionTerminator;
    private final HttpBringUp httpBringUp;
    private final SseBringUp sseBringUp;
    private final Object sseCallLock = new Object();
    private volatile IntSupplier sseProxyPort = () -> -1;
    private volatile BooleanSupplier serverPingsEnabled = () -> true;
    private volatile BooleanSupplier useBurpNetworking = () -> true;

    private final ReentrantLock connectLock = new ReentrantLock();
    private volatile ConnectionSnapshot snapshot = ConnectionSnapshot.disconnected(0);
    private long connectionGeneration;
    private final AtomicLong httpSnapshotSequence = new AtomicLong();
    private long publishedHttpSnapshotSequence;
    private String endpoint;
    private String sseUrl;
    private URI sseMessageEndpoint;
    private RedirectMode sseRedirectMode;
    private TransportType transportType;
    private AuthStrategy currentAuth;
    private final ScannerHeaderState headers = new ScannerHeaderState();
    private SseSession sseSession;
    private String negotiatedProtocolVersion;
    private McpFlow.Session protocolSession;
    private final Set<String> issuedSessionIds = ConcurrentHashMap.newKeySet();
    private volatile LegacySseRoutes legacySseRoutes = new LegacySseRoutes();
    private HttpSession httpSession;
    private GuardedCredentials credentials;
    private Map<String, Object> admissionEnvelope = Map.of();
    private final AtomicLong requestIdCounter = new AtomicLong(INITIALIZE_REQUEST_ID);

    public McpScannerSession(HttpClient httpClient, McpEventLog eventLog) {
        this(httpClient, eventLog, () -> true);
    }

    public McpScannerSession(HttpClient httpClient, McpEventLog eventLog, BooleanSupplier sseProxyAvailable) {
        this(httpClient, eventLog, sseProxyAvailable, DEFAULT_REQUEST_TIMEOUT);
    }

    McpScannerSession(HttpClient httpClient, McpEventLog eventLog, BooleanSupplier sseProxyAvailable,
                      Duration bodyReadTimeout) {
        this(httpClient, eventLog, sseProxyAvailable, bodyReadTimeout, ClientIdentityProvider.defaults());
    }

    public McpScannerSession(HttpClient httpClient, McpEventLog eventLog, BooleanSupplier sseProxyAvailable,
                             ClientIdentityProvider identityProvider) {
        this(httpClient, eventLog, sseProxyAvailable, DEFAULT_REQUEST_TIMEOUT, identityProvider);
    }

    McpScannerSession(HttpClient httpClient, McpEventLog eventLog, BooleanSupplier sseProxyAvailable,
                      Duration bodyReadTimeout, ClientIdentityProvider identityProvider) {
        this(httpClient, new JdkProtocolHttpTransport(httpClient), eventLog, sseProxyAvailable, bodyReadTimeout,
                identityProvider);
    }

    public McpScannerSession(HttpClient httpClient, ProtocolHttpTransport httpTransport, McpEventLog eventLog,
                             BooleanSupplier sseProxyAvailable, ClientIdentityProvider identityProvider) {
        this(httpClient, httpTransport, eventLog, sseProxyAvailable, DEFAULT_REQUEST_TIMEOUT, identityProvider);
    }

    McpScannerSession(HttpClient httpClient, ProtocolHttpTransport httpTransport, McpEventLog eventLog,
                      BooleanSupplier sseProxyAvailable, Duration bodyReadTimeout,
                      ClientIdentityProvider identityProvider) {
        this.identityProvider = identityProvider;
        this.eventLog = eventLog;
        this.redirectPolicy = new RedirectPolicy(eventLog);
        this.preconditions = new ConnectionPreconditions(sseProxyAvailable, eventLog);
        ServerPings serverPings = new ServerPings(() -> serverPingsEnabled.getAsBoolean());
        ProtocolHttpExchange httpExchange = redirectFollowingExchange(
                StaleConnectionResendingTransport.whenResendable(httpTransport, resendableRequests),
                bodyReadTimeout, serverPings);
        ProtocolHttpExchange sseMessageExchange = redirectFollowingExchange(
                new JdkProtocolHttpTransport(httpClient), bodyReadTimeout, serverPings);
        McpFlow flow = new McpFlow(BoundedBodyReader.MAX_RESPONSE_BYTES, 32);
        ConnectionAttemptSink attempts = new AttemptRecorder();
        this.sessionTerminator = new StreamableSessionTerminator(httpExchange, eventLog);
        this.httpBringUp = new HttpBringUp(flow, httpExchange, redirectFollowingExchange(
                StaleConnectionResendingTransport.always(httpTransport), bodyReadTimeout, serverPings), attempts);
        SseEndpointDiscoverer discoverer = new SseEndpointDiscoverer(httpClient, eventLog,
                new RedirectLoggingInterceptor(redirectPolicy));
        this.sseBringUp = new SseBringUp(flow, discoverer, sseMessageExchange, redirectPolicy, attempts, serverPings);
    }

    private ProtocolHttpExchange redirectFollowingExchange(ProtocolHttpTransport transport, Duration timeout,
                                                          ServerPings serverPings) {
        return new ProtocolHttpExchange(new RedirectFollowingTransport(transport, redirectPolicy), timeout,
                serverPings);
    }

    public void observeLegacySseRoutesWith(LegacySseRoutes routes) {
        legacySseRoutes = Objects.requireNonNull(routes, "routes");
    }

    public ResendableRequests resendableRequests() {
        return resendableRequests;
    }

    public McpEventLog eventLog() {
        return eventLog;
    }

    public ClientProfile clientProfile() {
        return identityProvider.current().profile();
    }

    public void setServerPingsEnabled(BooleanSupplier enabled) {
        serverPingsEnabled = Objects.requireNonNull(enabled, "enabled");
    }

    public void setUseBurpNetworking(BooleanSupplier enabled) {
        useBurpNetworking = Objects.requireNonNull(enabled, "enabled");
    }

    public void setRedirectModeSupplier(Supplier<RedirectMode> redirectMode) {
        redirectPolicy.setModeSupplier(redirectMode);
    }

    public void connect(McpServerConfig config) {
        connectLock.lock();
        try {
            establish(config);
        } finally {
            connectLock.unlock();
        }
    }

    private void establish(McpServerConfig config) {
        preconditions.rejectSseWhenProxyUnavailable(config.transport());
        disconnect();
        preconditions.rejectPlainHttpWithAuth(config.endpoint(), config.auth());
        beginConnection(config.auth());
        try {
            openTransport(config);
        } catch (RuntimeException failure) {
            if (config.transport() == TransportType.SSE) {
                logIfTlsSuspected(config.endpoint(), failure, sseTlsHint());
            }
            if (canFallBackToSse(config, failure) && openedSseFallback(config.endpoint(), failure)) {
                return;
            }
            disconnect();
            throw new IllegalStateException("Failed to establish scanner session for " + config.endpoint(), failure);
        }
    }

    private void openTransport(McpServerConfig config) {
        if (config.transport() == TransportType.SSE) {
            openSse(config.endpoint());
        } else {
            openHttp(config.endpoint(), config.transport());
        }
    }

    private boolean canFallBackToSse(McpServerConfig config, RuntimeException failure) {
        return config.transport() == TransportType.AUTO && !(failure instanceof ConnectionAuthException)
                && !(failure instanceof StaleConnectionException) && !BurpStreamingResponseException.caused(failure)
                && preconditions.sseProxyAvailable();
    }

    private boolean openedSseFallback(String target, RuntimeException httpFailure) {
        try {
            openSse(target);
            return true;
        } catch (RuntimeException sseFailure) {
            logIfTlsSuspected(target, sseFailure, sseFallbackTlsHint());
            httpFailure.addSuppressed(sseFailure);
            return false;
        }
    }

    private String sseTlsHint() {
        return useBurpNetworking.getAsBoolean() ? SSE_TLS_HINT : SSE_TLS_HINT_BURP_NETWORKING_OFF;
    }

    private String sseFallbackTlsHint() {
        return useBurpNetworking.getAsBoolean() ? SSE_FALLBACK_TLS_HINT : SSE_FALLBACK_TLS_HINT_BURP_NETWORKING_OFF;
    }

    private void logIfTlsSuspected(String sseEndpoint, RuntimeException sseFailure, String hint) {
        if (SseTlsFailureSuspicion.suspected(sseEndpoint, sseFailure)) {
            eventLog.error(hint);
        }
    }

    private synchronized void beginConnection(AuthStrategy auth) {
        currentAuth = auth;
        credentials = connectionCredentials(auth);
        headers.replaceHeaders(AuthHeaders.of(auth));
        requestIdCounter.set(FIRST_SCAN_REQUEST_ID);
    }

    public void disconnect() {
        Optional<Runnable> termination;
        synchronized (this) {
            termination = pendingSessionTermination();
            clearConnectionState();
        }
        termination.ifPresent(Runnable::run);
    }

    private Optional<Runnable> pendingSessionTermination() {
        String sessionId = activeStreamableSessionId();
        if (sessionId == null || endpoint == null) {
            return Optional.empty();
        }
        URI target = URI.create(endpoint);
        Map<String, String> baseHeaders = headers.snapshot();
        GuardedCredentials closingCredentials = credentials;
        return Optional.of(() -> sessionTerminator.terminate(target, sessionId, baseHeaders, closingCredentials));
    }

    private void clearConnectionState() {
        connectionGeneration++;
        endpoint = null;
        sseUrl = null;
        sseMessageEndpoint = null;
        sseRedirectMode = null;
        transportType = null;
        currentAuth = null;
        headers.clear();
        negotiatedProtocolVersion = null;
        protocolSession = null;
        httpSession = null;
        credentials = null;
        admissionEnvelope = Map.of();
        requestIdCounter.set(INITIALIZE_REQUEST_ID);
        closeSseSession();
        publishSnapshot();
    }

    private synchronized void publishSnapshot() {
        snapshot = new ConnectionSnapshot(connectionGeneration, endpoint, transportType, sseUrl,
                negotiatedProtocolVersion);
    }

    private String activeStreamableSessionId() {
        if (transportType != TransportType.STREAMABLE_HTTP
                || (credentials != null && credentials.hasRefusedCredentials())
                || (currentAuth != null && currentAuth.isTerminallyFailed())) {
            return null;
        }
        return headers.sessionId();
    }

    public synchronized String sessionId() {
        return headers.sessionId();
    }

    public long connectionGeneration() {
        return snapshot.generation();
    }

    public String resolvedEndpoint() {
        return snapshot.endpoint();
    }

    public void setSseProxyPort(IntSupplier sseProxyPort) {
        this.sseProxyPort = sseProxyPort != null ? sseProxyPort : () -> -1;
    }

    /**
     * On SSE the upstream message endpoint answers a POST with a bare 202 and delivers the reply on the
     * stream, so a self-issued probe must target the local proxy, which correlates the reply.
     */
    public Optional<HttpService> probeBaselineService() {
        int port = sseProxyPort.getAsInt();
        if (transportType() != TransportType.SSE || port <= 0) {
            return Optional.empty();
        }
        return Optional.of(HttpService.httpService(LOOPBACK, port, false));
    }

    public Optional<SseProbeStreams> probeSseStreams() {
        String target = sseUrl();
        if (transportType() != TransportType.SSE || target == null) {
            return Optional.empty();
        }
        return Optional.of(SseProbeStreams.at(target, headers -> sseBringUp.openProbeStream(target, headers)));
    }

    public String sseUrl() {
        return snapshot.sseUrl();
    }

    public TransportType transportType() {
        return snapshot.transportType();
    }

    public String negotiatedProtocolVersion() {
        return snapshot.negotiatedProtocolVersion();
    }

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> admissionResult() {
        Object result = admissionEnvelope.get("result");
        return result instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    public synchronized Map<String, Object> admissionEnvelope() {
        return admissionEnvelope;
    }

    public McpResponses.Reply catalog(String method, String cursor) {
        return exchange("Catalog request", id -> protocolSession.request(method, cursor, id));
    }

    public McpResponses.Reply call(String method, String paramsJson) {
        return exchange(method, id -> protocolSession.operation(method, paramsJson, id));
    }

    private McpResponses.Reply exchange(String requestLabel, LongFunction<McpRequests.Request> requestForId) {
        long id;
        McpRequests.Request request;
        HttpOperation operation = null;
        SseOperation sseOperation = null;
        synchronized (this) {
            requireProtocolSession();
            id = nextRequestId();
            request = requestForId.apply(id);
            if (transportType == TransportType.SSE) {
                sseOperation = new SseOperation(sseSession, connectionGeneration, sseRedirectMode);
            } else {
                operation = captureHttpOperation();
            }
        }
        return sseOperation != null
                ? exchangeOverSse(sseOperation, request, id)
                : exchangeOverHttp(requestLabel, operation, request, id);
    }

    private McpResponses.Reply exchangeOverSse(SseOperation operation, McpRequests.Request request, long id) {
        if (sseBringUp.redirectModeChanged(operation.redirectMode())) {
            disconnect();
            throw SseBringUp.redirectModeChangedFailure();
        }
        McpResponses.Reply reply;
        synchronized (sseCallLock) {
            reply = operation.session().call(request, id);
        }
        synchronized (this) {
            if (operation.generation() == connectionGeneration && operation.session() == sseSession) {
                updateSseSession();
            }
        }
        return reply;
    }

    private McpResponses.Reply exchangeOverHttp(String requestLabel, HttpOperation operation,
                                                McpRequests.Request request, long id) {
        McpFlow.HttpResponse response = sendHttpOperation(operation, request);
        if (!response.successful()) {
            throw new McpHttpStatusException(requestLabel, response.status());
        }
        McpResponses.Reply reply = McpResponses.parse(response.body(), BoundedBodyReader.MAX_RESPONSE_BYTES);
        if (reply.id() != id) {
            throw new IllegalStateException(requestLabel + " reply ID mismatch");
        }
        return reply;
    }

    public OperationRecovery beginAuthOperation() {
        GuardedCredentials current;
        synchronized (this) {
            current = credentials;
        }
        if (current == null) {
            throw new IllegalStateException("Scanner session is disconnected");
        }
        return current.beginOperation(UUID.randomUUID().toString());
    }

    public McpFlow.HttpResponse sendHttpOperation(McpRequests.Request request) {
        return prepareHttpOperation(request).get();
    }

    public synchronized Supplier<McpFlow.HttpResponse> prepareHttpOperation(McpRequests.Request request) {
        HttpOperation operation = captureHttpOperation();
        return () -> sendHttpOperation(operation, request);
    }

    private HttpOperation captureHttpOperation() {
        if (httpSession == null || transportType == TransportType.SSE) {
            throw new IllegalStateException("HTTP scanner session is disconnected");
        }
        return new HttpOperation(httpSession, connectionGeneration);
    }

    private McpFlow.HttpResponse sendHttpOperation(HttpOperation operation, McpRequests.Request request) {
        try {
            return operation.session().send(request);
        } finally {
            publishIfNewest(operation, snapshotHttpSession(operation.session()));
        }
    }

    private synchronized void publishIfNewest(HttpOperation operation, HttpSnapshot sessionSnapshot) {
        if (operation.generation() == connectionGeneration && operation.session() == httpSession
                && sessionSnapshot.sequence() > publishedHttpSnapshotSequence) {
            updateHttpSession(sessionSnapshot.session());
            publishedHttpSnapshotSequence = sessionSnapshot.sequence();
        }
    }

    private HttpSnapshot snapshotHttpSession(HttpSession session) {
        synchronized (session) {
            return new HttpSnapshot(session.session(), httpSnapshotSequence.incrementAndGet());
        }
    }

    private record HttpOperation(HttpSession session, long generation) { }
    private record SseOperation(SseSession session, long generation, RedirectMode redirectMode) { }
    private record HttpSnapshot(McpFlow.Session session, long sequence) { }

    @Override
    public synchronized McpRequests.Request operation(String method, String paramsJson, long id) {
        requireProtocolSession();
        return protocolSession.operation(method, paramsJson, id);
    }

    @Override
    public synchronized McpRequests.Request notification(String method, String paramsJson) {
        requireProtocolSession();
        return protocolSession.notification(method, paramsJson);
    }

    private void requireProtocolSession() {
        if (protocolSession == null) {
            throw new IllegalStateException("Scanner session is disconnected");
        }
    }

    public synchronized Map<String, String> protocolHeaders() {
        if (protocolSession == null) return Map.of();
        Map<String, String> protocol = new LinkedHashMap<>();
        protocol.put(McpHeaders.PROTOCOL_VERSION, protocolSession.version());
        if (protocolSession.sessionId() != null) {
            protocol.put(McpHeaders.SESSION_ID, protocolSession.sessionId());
        }
        return Map.copyOf(protocol);
    }

    public boolean isIssuedSessionId(String sessionId) {
        return sessionId != null && issuedSessionIds.contains(sessionId);
    }

    public synchronized Set<String> credentialHeaderNames() {
        return headers.credentialHeaderNames();
    }

    public Map<String, String> scannerHeaders() {
        Map<String, String> baseHeaders;
        GuardedCredentials current;
        synchronized (this) {
            baseHeaders = headers.snapshot();
            current = credentials;
        }
        return ScannerHeaderState.withCredentials(baseHeaders, current);
    }

    public long nextRequestId() {
        return requestIdCounter.getAndIncrement();
    }

    private boolean refreshAuth(AuthStrategy auth, long generation) {
        if (!isCurrentAuth(auth, generation) || !auth.supportsRefresh() || auth.isTerminallyFailed()) {
            return false;
        }
        eventLog.info("Auth refresh attempted after 401");
        if (!auth.refresh()) {
            eventLog.warn("Auth refresh failed");
            return false;
        }
        if (!applyRefreshedHeaders(auth, generation, AuthHeaders.of(auth))) {
            return false;
        }
        eventLog.info("Auth refresh succeeded");
        return true;
    }

    private synchronized boolean isCurrentAuth(AuthStrategy auth, long generation) {
        return auth == currentAuth && generation == connectionGeneration;
    }

    private synchronized boolean applyRefreshedHeaders(AuthStrategy auth, long generation,
                                                       Map<String, String> refreshed) {
        if (!isCurrentAuth(auth, generation)) {
            return false;
        }
        headers.putAll(refreshed);
        return true;
    }

    private GuardedCredentials connectionCredentials(AuthStrategy auth) {
        long generation = connectionGeneration;
        CredentialProvider provider = auth.sharedCredentialProvider().orElseGet(() ->
                new ScannerCredentials(auth, () -> refreshAuth(auth, generation)));
        return new GuardedCredentials(provider);
    }

    private void openHttp(String target, TransportType requestedTransport) {
        ConnectionAttempt attempt = beginHttpAttempt(target);
        adoptHttpSession(attempt, httpBringUp.open(attempt, requestedTransport, clientProfile()));
    }

    private synchronized ConnectionAttempt beginHttpAttempt(String target) {
        ConnectionAttempt attempt = currentAttempt();
        endpoint = target;
        publishSnapshot();
        return attempt;
    }

    private synchronized void adoptHttpSession(ConnectionAttempt attempt, HttpSession selected) {
        requireCurrent(attempt);
        httpSession = selected;
        updateHttpSession(httpSession.session());
    }

    private synchronized ConnectionAttempt currentAttempt() {
        if (credentials == null) {
            throw new StaleConnectionException();
        }
        return new ConnectionAttempt(connectionGeneration, credentials);
    }

    private void requireCurrent(ConnectionAttempt attempt) {
        if (!isCurrent(attempt)) {
            throw new StaleConnectionException();
        }
    }

    private boolean isCurrent(ConnectionAttempt attempt) {
        return attempt.generation() == connectionGeneration && attempt.credentials() == credentials;
    }

    private void updateHttpSession(McpFlow.Session selected) {
        protocolSession = selected;
        negotiatedProtocolVersion = protocolSession.version();
        transportType = McpRequests.MODERN_VERSION.equals(negotiatedProtocolVersion)
                ? TransportType.MODERN_HTTP : TransportType.STREAMABLE_HTTP;
        headers.adoptProtocol(negotiatedProtocolVersion, protocolSession.sessionId());
        Optional.ofNullable(protocolSession.sessionId()).ifPresent(issuedSessionIds::add);
        publishSnapshot();
    }

    private void adoptSameHostRedirect(URI reachedUri) {
        if (sharesHostWithEndpoint(reachedUri)) {
            endpoint = reachedUri.toString();
            publishSnapshot();
        }
    }

    private boolean sharesHostWithEndpoint(URI reachedUri) {
        Optional<String> reachedHost = HttpOrigin.parse(reachedUri).map(HttpOrigin::host);
        return reachedHost.isPresent() && reachedHost.equals(HttpOrigin.parse(endpoint).map(HttpOrigin::host));
    }

    private void openSse(String target) {
        preconditions.rejectSseWhenProxyUnavailable(TransportType.SSE);
        ConnectionAttempt attempt = currentAttempt();
        RedirectMode redirectMode = redirectPolicy.mode();
        SseSession opened = sseBringUp.open(target, attempt, redirectMode, clientProfile());
        try {
            sseBringUp.requireRedirectMode(redirectMode);
            adoptSseSession(attempt, opened, target, redirectMode);
        } catch (RuntimeException failure) {
            opened.close();
            throw failure;
        }
    }

    private synchronized void adoptSseSession(ConnectionAttempt attempt, SseSession opened, String target,
                                              RedirectMode redirectMode) {
        requireCurrent(attempt);
        sseSession = opened;
        sseRedirectMode = redirectMode;
        sseUrl = target;
        updateSseSession();
    }

    private void updateSseSession() {
        protocolSession = sseSession.session();
        endpoint = sseMessageEndpoint.toString();
        transportType = TransportType.SSE;
        negotiatedProtocolVersion = protocolSession.version();
        headers.adoptProtocolVersion(negotiatedProtocolVersion);
        publishSnapshot();
    }

    @SuppressWarnings("unchecked")
    private void captureAdmission(String json) {
        if (json == null || json.isBlank()) return;
        try {
            admissionEnvelope = McpObjectMapper.INSTANCE.readValue(json, Map.class);
        } catch (IOException ignored) {
            admissionEnvelope = Map.of();
        }
    }

    private void closeSseSession() {
        if (sseSession != null) {
            sseSession.close();
            sseSession = null;
        }
    }

    private final class AttemptRecorder implements ConnectionAttemptSink {

        @Override
        public URI endpointFor(ConnectionAttempt attempt) {
            synchronized (McpScannerSession.this) {
                requireCurrent(attempt);
                return URI.create(endpoint);
            }
        }

        @Override
        public void rememberCredentials(ConnectionAttempt attempt, Map<String, String> requestHeaders) {
            Set<String> names = attempt.credentials().headerNames();
            synchronized (McpScannerSession.this) {
                if (isCurrent(attempt)) {
                    headers.rememberCredentials(requestHeaders, names);
                }
            }
        }

        @Override
        public void recordAdmission(ConnectionAttempt attempt, String body, URI reachedUri) {
            synchronized (McpScannerSession.this) {
                if (isCurrent(attempt)) {
                    captureAdmission(body);
                    adoptSameHostRedirect(reachedUri);
                }
            }
        }

        @Override
        public void recordSseMessageEndpoint(ConnectionAttempt attempt, URI messageUrl) {
            synchronized (McpScannerSession.this) {
                requireCurrent(attempt);
                sseMessageEndpoint = messageUrl;
                legacySseRoutes.observe(messageUrl.toString());
            }
        }

        @Override
        public void recordSseAdmission(ConnectionAttempt attempt, String json) {
            synchronized (McpScannerSession.this) {
                if (isCurrent(attempt)) {
                    captureAdmission(json);
                }
            }
        }
    }
}
