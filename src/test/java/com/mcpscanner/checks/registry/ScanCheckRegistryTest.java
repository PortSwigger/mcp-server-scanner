package com.mcpscanner.checks.registry;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class ScanCheckRegistryTest {

    // Eleven checks dispatch from the active-check block of the list, but two of them
    // (dcr-misconfiguration idx 7, consent-page-reflected-xss idx 8) are scan-start-only
    // ManagedScanStartChecks — they are NOT Burp ActiveScanChecks and register no per-request
    // surface, so only the remaining nine reach scanner.registerActiveScanCheck.
    private static final int ACTIVE_CHECK_COUNT = 11;
    private static final int REGISTERED_ACTIVE_SCAN_CHECK_COUNT = 9;
    private static final int DISCOVERY_CONTENT_CHECK_COUNT = 2;
    private static final int TOTAL_CHECK_COUNT = ACTIVE_CHECK_COUNT + DISCOVERY_CONTENT_CHECK_COUNT;
    private static final List<String> DISCOVERY_CONTENT_RULE_IDS = List.of(
            "discovery-content-scanner",
            "response-content-scanner"
    );

    private Supplier<AuthStrategy> authSupplier;
    private ScanCheckSettings settings;
    private ScanCheckRegistry registry;

    @BeforeEach
    void setUp() {
        authSupplier = NoAuthStrategy::new;
        settings = mock(ScanCheckSettings.class);
        registry = new ScanCheckRegistry(authSupplier, settings);
    }

    @Test
    void allReturnsActiveChecksFollowedByDiscoveryContentChecksInDocumentedOrder() {
        List<ManagedCheck> all = registry.all();

        assertThat(all).hasSize(TOTAL_CHECK_COUNT);
        assertThat(all.get(0).descriptor().id()).isEqualTo("unauth-tool-discovery");
        assertThat(all.get(1).descriptor().id()).isEqualTo("auth-bypass");
        assertThat(all.get(2).descriptor().id()).isEqualTo("hidden-method");
        assertThat(all.get(3).descriptor().id()).isEqualTo("resource-traversal");
        assertThat(all.get(4).descriptor().id()).isEqualTo("oauth-token-validation");
        assertThat(all.get(5).descriptor().id()).isEqualTo("dns-rebinding");
        assertThat(all.get(6).descriptor().id()).isEqualTo("oauth-metadata-ssrf");
        assertThat(all.get(7).descriptor().id()).isEqualTo("dcr-misconfiguration");
        assertThat(all.get(8).descriptor().id()).isEqualTo("consent-page-reflected-xss");
        assertThat(all.get(9).descriptor().id()).isEqualTo("tool-arg-traversal");
        assertThat(all.get(10).descriptor().id()).isEqualTo("tool-arg-rce");
        for (int i = 0; i < DISCOVERY_CONTENT_RULE_IDS.size(); i++) {
            assertThat(all.get(ACTIVE_CHECK_COUNT + i).descriptor().id())
                    .isEqualTo(DISCOVERY_CONTENT_RULE_IDS.get(i));
        }
    }

    @Test
    void activeEntriesAreActiveScanChecksExceptScanStartOnlyChecks() {
        List<ManagedCheck> all = registry.all();
        for (int i = 0; i < ACTIVE_CHECK_COUNT; i++) {
            String id = all.get(i).descriptor().id();
            if (id.equals("dcr-misconfiguration") || id.equals("consent-page-reflected-xss")) {
                assertThat(all.get(i)).isNotInstanceOf(ActiveScanCheck.class);
            } else {
                assertThat(all.get(i)).isInstanceOf(ActiveScanCheck.class);
            }
        }
    }

    @Test
    void discoveryContentEntriesArePassiveScanChecks() {
        List<ManagedCheck> all = registry.all();
        for (int i = ACTIVE_CHECK_COUNT; i < TOTAL_CHECK_COUNT; i++) {
            assertThat(all.get(i)).isInstanceOf(PassiveScanCheck.class);
        }
    }

    @Test
    void descriptorsCarryDocumentedScopesAndDefaults() {
        List<ManagedCheck> all = registry.all();

        // T-deadcheck: unauth-tool-discovery (0), resource-traversal (3), tool-arg-traversal (9)
        // and tool-arg-rce (10) moved from PER_HOST to PER_REQUEST. PER_HOST-only checks with no
        // scan-start hook were never invoked — Burp's audit (built via McpScanLauncher
        // addRequest) only drives the PER_REQUEST path. Internal HostDedup keeps each
        // self-discovering battery single-fire per host.
        CheckDescriptor unauthToolDiscovery = all.get(0).descriptor();
        assertThat(unauthToolDiscovery.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(unauthToolDiscovery.defaultEnabled()).isTrue();
        assertThat(unauthToolDiscovery.headlineSeverity()).isEqualTo(AuditIssueSeverity.INFORMATION);

        CheckDescriptor authBypass = all.get(1).descriptor();
        assertThat(authBypass.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(authBypass.defaultEnabled()).isTrue();

        // T14: hidden-method moved from PER_HOST to PER_REQUEST for the same
        // reason as the T5 (e745250) sibling migrations — PER_HOST is silently
        // skipped by Burp's audit pipeline in "Active Scan from captured
        // request" mode. Internal HostDedup keeps the wordlist single-fire.
        CheckDescriptor hiddenMethod = all.get(2).descriptor();
        assertThat(hiddenMethod.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(hiddenMethod.defaultEnabled()).isTrue();

        CheckDescriptor resourceTraversal = all.get(3).descriptor();
        assertThat(resourceTraversal.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(resourceTraversal.defaultEnabled()).isTrue();

        CheckDescriptor oauthTokenValidation = all.get(4).descriptor();
        assertThat(oauthTokenValidation.scope()).isEqualTo(ScanCheckType.PER_HOST);
        assertThat(oauthTokenValidation.defaultEnabled()).isTrue();

        // T5: DnsRebinding, OAuthMetadataSsrf, and DcrMisconfiguration now dispatch
        // PER_REQUEST with internal HostDedup. PER_HOST was silently skipped in many
        // Active-Scan-from-captured-request modes.
        CheckDescriptor dnsRebinding = all.get(5).descriptor();
        assertThat(dnsRebinding.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(dnsRebinding.defaultEnabled()).isTrue();
        assertThat(dnsRebinding.headlineSeverity()).isEqualTo(AuditIssueSeverity.MEDIUM);

        CheckDescriptor oauthMetadataSsrf = all.get(6).descriptor();
        assertThat(oauthMetadataSsrf.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(oauthMetadataSsrf.defaultEnabled()).isTrue();
        assertThat(oauthMetadataSsrf.headlineSeverity()).isEqualTo(AuditIssueSeverity.MEDIUM);

        CheckDescriptor dcrMisconfiguration = all.get(7).descriptor();
        assertThat(dcrMisconfiguration.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(dcrMisconfiguration.defaultEnabled()).isTrue();
        assertThat(dcrMisconfiguration.headlineSeverity()).isEqualTo(AuditIssueSeverity.MEDIUM);

        CheckDescriptor consentPageXss = all.get(8).descriptor();
        assertThat(consentPageXss.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(consentPageXss.defaultEnabled()).isTrue();
        assertThat(consentPageXss.headlineSeverity()).isEqualTo(AuditIssueSeverity.HIGH);

        CheckDescriptor toolArgTraversal = all.get(9).descriptor();
        assertThat(toolArgTraversal.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(toolArgTraversal.defaultEnabled()).isTrue();
        assertThat(toolArgTraversal.headlineSeverity()).isEqualTo(AuditIssueSeverity.HIGH);

        CheckDescriptor toolArgRce = all.get(10).descriptor();
        assertThat(toolArgRce.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(toolArgRce.defaultEnabled()).isTrue();
        assertThat(toolArgRce.headlineSeverity()).isEqualTo(AuditIssueSeverity.HIGH);

        CheckDescriptor discoveryContent = all.get(ACTIVE_CHECK_COUNT).descriptor();
        assertThat(discoveryContent.headlineSeverity()).isEqualTo(AuditIssueSeverity.MEDIUM);
    }

    @Test
    void descriptorsExposeResearchReferences() {
        List<ManagedCheck> all = registry.all();

        CheckDescriptor unauthToolDiscovery = all.get(0).descriptor();
        assertThat(unauthToolDiscovery.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-handling",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
                "https://cwe.mitre.org/data/definitions/306.html"
        );

        CheckDescriptor authBypass = all.get(1).descriptor();
        assertThat(authBypass.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-handling",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#token-passthrough",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking",
                "https://datatracker.ietf.org/doc/html/rfc6750#section-2.1"
        );

        CheckDescriptor hiddenMethod = all.get(2).descriptor();
        assertThat(hiddenMethod.references()).containsExactly(
                "https://www.jsonrpc.org/specification",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic",
                "https://cwe.mitre.org/data/definitions/749.html"
        );

        CheckDescriptor resourceTraversal = all.get(3).descriptor();
        assertThat(resourceTraversal.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/server/resources#security-considerations",
                "https://portswigger.net/web-security/file-path-traversal",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-53110"
        );

        CheckDescriptor oauthTokenValidation = all.get(4).descriptor();
        assertThat(oauthTokenValidation.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#access-token-privilege-restriction",
                "https://datatracker.ietf.org/doc/html/rfc9068",
                "https://datatracker.ietf.org/doc/html/rfc8725",
                "https://datatracker.ietf.org/doc/html/rfc9700#section-2.3",
                "https://portswigger.net/web-security/jwt"
        );

        CheckDescriptor dnsRebinding = all.get(5).descriptor();
        assertThat(dnsRebinding.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#security-warning",
                "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w",
                "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-9h52-p55h-vw2f",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-49596"
        );

        CheckDescriptor oauthMetadataSsrf = all.get(6).descriptor();
        assertThat(oauthMetadataSsrf.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                "https://datatracker.ietf.org/doc/html/rfc9728#section-7.7",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
                "https://portswigger.net/research/hidden-oauth-attack-vectors"
        );

        CheckDescriptor dcrMisconfiguration = all.get(7).descriptor();
        assertThat(dcrMisconfiguration.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#security-considerations",
                "https://datatracker.ietf.org/doc/rfc9700/",
                "https://datatracker.ietf.org/doc/html/rfc7591#section-3",
                "https://portswigger.net/web-security/oauth"
        );

        CheckDescriptor consentPageXss = all.get(8).descriptor();
        assertThat(consentPageXss.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                "https://datatracker.ietf.org/doc/html/rfc7591#section-2",
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting/reflected"
        );

        CheckDescriptor toolArgTraversal = all.get(9).descriptor();
        assertThat(toolArgTraversal.references()).containsExactly(
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://portswigger.net/web-security/file-path-traversal",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-53110"
        );

        CheckDescriptor toolArgRce = all.get(10).descriptor();
        assertThat(toolArgRce.references()).containsExactly(
                "https://owasp.org/www-community/attacks/Code_Injection",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-6514"
        );
    }

    @Test
    void registerWithRegistersActiveChecksWithMatchingScope() {
        MontoyaApi api = mock(MontoyaApi.class);
        Scanner scanner = mock(Scanner.class);
        when(api.scanner()).thenReturn(scanner);

        registry.registerWith(api);

        verify(scanner, times(REGISTERED_ACTIVE_SCAN_CHECK_COUNT))
                .registerActiveScanCheck(any(ActiveScanCheck.class), any(ScanCheckType.class));

        List<ManagedCheck> all = registry.all();
        // T-deadcheck: unauth-tool-discovery (0) converted to PER_REQUEST with internal HostDedup.
        verify(scanner).registerActiveScanCheck((ActiveScanCheck) all.get(0), ScanCheckType.PER_REQUEST);
        verify(scanner).registerActiveScanCheck((ActiveScanCheck) all.get(1), ScanCheckType.PER_REQUEST);
        // T14: hidden-method (2) converted to PER_REQUEST with internal HostDedup.
        verify(scanner).registerActiveScanCheck((ActiveScanCheck) all.get(2), ScanCheckType.PER_REQUEST);
        // T-deadcheck: resource-traversal (3) converted to PER_REQUEST with internal HostDedup.
        verify(scanner).registerActiveScanCheck((ActiveScanCheck) all.get(3), ScanCheckType.PER_REQUEST);
        verify(scanner).registerActiveScanCheck((ActiveScanCheck) all.get(4), ScanCheckType.PER_HOST);
        // T5: dns-rebinding (5), oauth-metadata-ssrf (6) dispatch PER_REQUEST with internal HostDedup.
        verify(scanner).registerActiveScanCheck((ActiveScanCheck) all.get(5), ScanCheckType.PER_REQUEST);
        verify(scanner).registerActiveScanCheck((ActiveScanCheck) all.get(6), ScanCheckType.PER_REQUEST);
        // dcr-misconfiguration (7) and consent-page-reflected-xss (8) are scan-start-only
        // ManagedScanStartChecks — registerWith is a no-op, so they never reach the scanner.
        // T-deadcheck: tool-arg-traversal (9) and tool-arg-rce (10) converted to PER_REQUEST
        // with internal HostDedup.
        verify(scanner).registerActiveScanCheck((ActiveScanCheck) all.get(9), ScanCheckType.PER_REQUEST);
        verify(scanner).registerActiveScanCheck((ActiveScanCheck) all.get(10), ScanCheckType.PER_REQUEST);
    }

    @Test
    void registerWithRegistersDiscoveryContentStubsAsPassiveChecks() {
        MontoyaApi api = mock(MontoyaApi.class);
        Scanner scanner = mock(Scanner.class);
        when(api.scanner()).thenReturn(scanner);

        registry.registerWith(api);

        verify(scanner, times(REGISTERED_ACTIVE_SCAN_CHECK_COUNT))
                .registerActiveScanCheck(any(ActiveScanCheck.class), any(ScanCheckType.class));
        verify(scanner, times(DISCOVERY_CONTENT_CHECK_COUNT))
                .registerPassiveScanCheck(any(PassiveScanCheck.class), any(ScanCheckType.class));
        verifyNoMoreInteractions(scanner);
        List<ManagedCheck> all = registry.all();
        for (int i = ACTIVE_CHECK_COUNT; i < TOTAL_CHECK_COUNT; i++) {
            verify(scanner).registerPassiveScanCheck(
                    (PassiveScanCheck) all.get(i), ScanCheckType.PER_HOST);
        }
    }

    @Test
    void constructorRejectsNullAuthSupplier() {
        assertThatThrownBy(() -> new ScanCheckRegistry(null, settings))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void constructorRejectsNullSettings() {
        assertThatThrownBy(() -> new ScanCheckRegistry(authSupplier, null))
                .isInstanceOf(NullPointerException.class);
    }
}
