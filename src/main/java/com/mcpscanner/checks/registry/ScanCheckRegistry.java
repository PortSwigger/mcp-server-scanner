package com.mcpscanner.checks.registry;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.oauth.OAuthUrlValidator;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.checks.JsonRpcDiscoveryResponseScanner;
import com.mcpscanner.checks.JsonRpcResponseContentScanner;
import com.mcpscanner.checks.McpActiveAuthBypassCheck;
import com.mcpscanner.checks.McpActiveConsentPageReflectedXssCheck;
import com.mcpscanner.checks.McpActiveDcrMisconfigurationCheck;
import com.mcpscanner.checks.McpActiveDnsRebindingCheck;
import com.mcpscanner.checks.McpActiveHiddenMethodCheck;
import com.mcpscanner.checks.McpActiveOAuthMetadataSsrfCheck;
import com.mcpscanner.checks.McpActiveOAuthTokenValidationCheck;
import com.mcpscanner.checks.McpActiveResourcePathTraversalCheck;
import com.mcpscanner.checks.McpActiveToolArgumentPathTraversalCheck;
import com.mcpscanner.checks.McpActiveToolArgumentRceCheck;
import com.mcpscanner.checks.McpActiveUnauthenticatedToolDiscoveryCheck;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanStartCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

public final class ScanCheckRegistry {

    private final List<ManagedCheck> checks;
    private final ScanCheckSettings settings;

    public ScanCheckRegistry(Supplier<AuthStrategy> authSupplier,
                             ScanCheckSettings settings) {
        this(authSupplier, settings, null, () -> null, ScanInventory::empty);
    }

    public ScanCheckRegistry(Supplier<AuthStrategy> authSupplier,
                             ScanCheckSettings settings,
                             McpEventLog eventLog) {
        this(authSupplier, settings, eventLog, () -> null, ScanInventory::empty);
    }

    public ScanCheckRegistry(Supplier<AuthStrategy> authSupplier,
                             ScanCheckSettings settings,
                             McpEventLog eventLog,
                             Supplier<CollaboratorClient> collaboratorSupplier) {
        this(authSupplier, settings, eventLog, collaboratorSupplier, ScanInventory::empty);
    }

    public ScanCheckRegistry(Supplier<AuthStrategy> authSupplier,
                             ScanCheckSettings settings,
                             McpEventLog eventLog,
                             Supplier<CollaboratorClient> collaboratorSupplier,
                             Supplier<ScanInventory> selectedInventorySupplier) {
        this(authSupplier, settings, eventLog, collaboratorSupplier, selectedInventorySupplier,
                new JsonRpcDiscoveryResponseScanner(settings, eventLog));
    }

    public ScanCheckRegistry(Supplier<AuthStrategy> authSupplier,
                             ScanCheckSettings settings,
                             McpEventLog eventLog,
                             Supplier<CollaboratorClient> collaboratorSupplier,
                             Supplier<ScanInventory> selectedInventorySupplier,
                             JsonRpcDiscoveryResponseScanner discoveryContentScanner) {
        this(authSupplier, settings, eventLog, collaboratorSupplier, selectedInventorySupplier,
                discoveryContentScanner, () -> null);
    }

    public ScanCheckRegistry(Supplier<AuthStrategy> authSupplier,
                             ScanCheckSettings settings,
                             McpEventLog eventLog,
                             Supplier<CollaboratorClient> collaboratorSupplier,
                             Supplier<ScanInventory> selectedInventorySupplier,
                             JsonRpcDiscoveryResponseScanner discoveryContentScanner,
                             Supplier<TransportType> transportSupplier) {
        this(authSupplier, settings, eventLog, collaboratorSupplier, selectedInventorySupplier,
                discoveryContentScanner, transportSupplier, Optional::empty);
    }

    /**
     * @param discoveryContentScanner the passive discovery-content check, supplied pre-built by
     * the caller so its {@code ContentFindingDedup} can be shared with the connect-time
     * {@code DiscoveryContentScanner}. Injected as the concrete check (not the dedup type) so
     * {@code registry/} never imports {@code content/} — preserving the checks/ slice DAG.
     * @param transportSupplier yields the active {@link TransportType} so the auth-bypass and
     * unauthenticated-discovery checks can caveat their findings on the SSE transport (where the
     * local proxy preserves Mcp-Session-Id). May yield {@code null} before a connection exists.
     * @param probeServiceSupplier yields the local SSE-proxy {@link HttpService} self-issued probe
     * checks must target on SSE (empty on Streamable HTTP), so {@code Http.sendRequest} reaches the
     * proxy that lifts the {@code /sse} reply instead of POSTing to the bare-202 upstream endpoint.
     */
    public ScanCheckRegistry(Supplier<AuthStrategy> authSupplier,
                             ScanCheckSettings settings,
                             McpEventLog eventLog,
                             Supplier<CollaboratorClient> collaboratorSupplier,
                             Supplier<ScanInventory> selectedInventorySupplier,
                             JsonRpcDiscoveryResponseScanner discoveryContentScanner,
                             Supplier<TransportType> transportSupplier,
                             Supplier<Optional<HttpService>> probeServiceSupplier) {
        Objects.requireNonNull(authSupplier, "authSupplier must not be null");
        Objects.requireNonNull(settings, "settings must not be null");
        Objects.requireNonNull(collaboratorSupplier, "collaboratorSupplier must not be null");
        Objects.requireNonNull(selectedInventorySupplier, "selectedInventorySupplier must not be null");
        Objects.requireNonNull(discoveryContentScanner, "discoveryContentScanner must not be null");
        Objects.requireNonNull(transportSupplier, "transportSupplier must not be null");
        Objects.requireNonNull(probeServiceSupplier, "probeServiceSupplier must not be null");
        this.settings = settings;
        this.checks = buildChecks(authSupplier, settings, eventLog, collaboratorSupplier,
                selectedInventorySupplier, discoveryContentScanner, transportSupplier, probeServiceSupplier);
    }

    public List<ManagedCheck> all() {
        return checks;
    }

    /**
     * @return the subset of registered checks that implement {@link ScanStartCheck}, in
     * registration order. The launcher invokes these once per scan-start before queueing
     * audit requests. Scan-start-only checks (e.g. {@code ManagedScanStartCheck} subclasses)
     * run exclusively here; checks that are also {@code ManagedActiveCheck}s additionally stay
     * registered with Burp's per-request scanner for manually-scanned baselines.
     */
    public List<ScanStartCheck> scanStartChecks() {
        return checks.stream()
                .filter(ScanStartCheck.class::isInstance)
                .map(ScanStartCheck.class::cast)
                .toList();
    }

    /**
     * @return the number of enabled checks that run during a scan — both Burp per-request
     * {@link ActiveScanCheck}s and scan-start {@link ScanStartCheck}s — so the user-facing
     * "started" message counts every active probe regardless of which surface drives it.
     * Passive discovery-content scanners are excluded.
     */
    public long enabledActiveCheckCount() {
        return checks.stream()
                .filter(check -> check instanceof ActiveScanCheck || check instanceof ScanStartCheck)
                .map(ManagedCheck::descriptor)
                .filter(descriptor -> settings.isEnabled(descriptor.id(), descriptor.defaultEnabled()))
                .count();
    }

    public void registerWith(MontoyaApi api) {
        for (ManagedCheck check : checks) {
            check.registerWith(api.scanner());
        }
    }

    /**
     * Clears the per-connection dedup state of every {@link SessionScopedCheck} so a reconnect
     * re-probes from scratch and the claim sets do not grow unbounded across a long-lived project.
     * Wired into the client's disconnect listeners.
     */
    public void clearSessionState() {
        checks.stream()
                .filter(SessionScopedCheck.class::isInstance)
                .map(SessionScopedCheck.class::cast)
                .forEach(SessionScopedCheck::clearSessionState);
    }

    private static List<ManagedCheck> buildChecks(Supplier<AuthStrategy> authSupplier,
                                                  ScanCheckSettings settings,
                                                  McpEventLog eventLog,
                                                  Supplier<CollaboratorClient> collaboratorSupplier,
                                                  Supplier<ScanInventory> selectedInventorySupplier,
                                                  JsonRpcDiscoveryResponseScanner discoveryContentScanner,
                                                  Supplier<TransportType> transportSupplier,
                                                  Supplier<Optional<HttpService>> probeServiceSupplier) {
        List<ManagedCheck> checks = new ArrayList<>();
        checks.add(new McpActiveUnauthenticatedToolDiscoveryCheck(
                settings, authSupplier, eventLog, transportSupplier, probeServiceSupplier));
        checks.add(new McpActiveAuthBypassCheck(settings, authSupplier, eventLog));
        checks.add(new McpActiveHiddenMethodCheck(settings, eventLog));
        checks.add(new McpActiveResourcePathTraversalCheck(
                settings, eventLog, selectedInventorySupplier, probeServiceSupplier));
        checks.add(new McpActiveOAuthTokenValidationCheck(settings, authSupplier, eventLog));
        checks.add(new McpActiveDnsRebindingCheck(settings, eventLog));
        checks.add(new McpActiveOAuthMetadataSsrfCheck(settings, authSupplier,
                new OAuthUrlValidator(), eventLog));
        checks.add(new McpActiveDcrMisconfigurationCheck(settings, eventLog, authSupplier));
        checks.add(new McpActiveConsentPageReflectedXssCheck(settings, eventLog, authSupplier));
        checks.add(new McpActiveToolArgumentPathTraversalCheck(settings, eventLog, selectedInventorySupplier));
        checks.add(new McpActiveToolArgumentRceCheck(settings, eventLog, collaboratorSupplier, selectedInventorySupplier));
        checks.add(discoveryContentScanner);
        checks.add(new JsonRpcResponseContentScanner(settings, eventLog));
        return List.copyOf(checks);
    }
}
