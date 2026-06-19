package com.mcpscanner.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.DoNotIncludeTests.class)
public class LayeringTest {

    @ArchTest
    static final ArchRule mcp_package_is_a_leaf =
            noClasses().that().resideInAPackage("com.mcpscanner.mcp..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "com.mcpscanner.auth..",
                            "com.mcpscanner.checks..",
                            "com.mcpscanner.client..",
                            "com.mcpscanner.config..",
                            "com.mcpscanner.logging..",
                            "com.mcpscanner.proxy..",
                            "com.mcpscanner.scan..",
                            "com.mcpscanner.ui..")
                    .because("mcp/ defines the protocol surface (request detection, JSON-RPC framing, SSE "
                            + "parsing, shared Jackson singleton) and must stay reachable from every other "
                            + "package without itself reaching back. It is a pure leaf with only JDK + Jackson "
                            + "dependencies.");

    @ArchTest
    static final ArchRule config_package_is_a_near_leaf =
            noClasses().that().resideInAPackage("com.mcpscanner.config..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "com.mcpscanner.checks..",
                            "com.mcpscanner.client..",
                            "com.mcpscanner.logging..",
                            "com.mcpscanner.proxy..",
                            "com.mcpscanner.ui..")
                    .because("config/ persists user input via Burp's Persistence API. It may reach mcp.McpObjectMapper "
                            + "for Jackson and auth.oauth.OAuthClientHints for the default redirect-port constant, "
                            + "but must not depend on any session-state or UI package.");

    @ArchTest
    static final ArchRule oauth_internals_not_reached_from_lowlevel_packages =
            noClasses().that().resideInAnyPackage(
                            "com.mcpscanner.client..",
                            "com.mcpscanner.logging..",
                            "com.mcpscanner.mcp..",
                            "com.mcpscanner.proxy..",
                            "com.mcpscanner.scan..")
                    .should().dependOnClassesThat().resideInAPackage("com.mcpscanner.auth.oauth..")
                    .because("OAuth flow machinery is owned by auth/ and consumed by ui/ + checks/. Low-level "
                            + "transport packages must remain auth-strategy-agnostic so the protocol layer can be "
                            + "exercised without an OAuth flow in the loop.");

    @ArchTest
    static final ArchRule ui_is_a_leaf_except_for_extension_root =
            noClasses().that().resideOutsideOfPackage("com.mcpscanner.ui..")
                    .and().doNotHaveFullyQualifiedName("com.mcpscanner.McpScannerExtension")
                    .should().dependOnClassesThat().resideInAPackage("com.mcpscanner.ui..")
                    .because("Only the BurpExtension entry point may construct McpScannerTab. No other package "
                            + "should reach into Swing widgets — UI state changes flow through ui.state reducers.");

    @ArchTest
    static final ArchRule checks_do_not_depend_on_session_state =
            noClasses().that().resideInAPackage("com.mcpscanner.checks..")
                    .should().dependOnClassesThat().haveFullyQualifiedName("com.mcpscanner.client.McpClientManager")
                    .orShould().dependOnClassesThat().haveFullyQualifiedName("com.mcpscanner.client.McpDiscoveryClient")
                    .orShould().dependOnClassesThat().haveFullyQualifiedName("com.mcpscanner.client.McpScannerSession")
                    .orShould().dependOnClassesThat().haveFullyQualifiedName("com.mcpscanner.proxy.SseScanSession")
                    .orShould().dependOnClassesThat().haveFullyQualifiedName("com.mcpscanner.proxy.SseProxyServer")
                    .orShould().dependOnClassesThat().haveFullyQualifiedName("com.mcpscanner.proxy.McpHttpHandler")
                    .orShould().dependOnClassesThat().resideInAPackage("com.mcpscanner.ui..")
                    .because("Scan checks must be pure functions of the HTTP request/response Burp hands them. "
                            + "Reaching into session-holding classes (McpClientManager, McpScannerSession, "
                            + "SseScanSession) or the UI layer would couple a check to live connection state and "
                            + "make it untestable against a synthetic HttpRequestResponse. Stateless utilities "
                            + "for SSE framing now live in mcp/ where they are freely reachable.");

    @ArchTest
    static final ArchRule client_does_not_depend_on_checks =
            noClasses().that().resideInAPackage("com.mcpscanner.client..")
                    .should().dependOnClassesThat().resideInAPackage("com.mcpscanner.checks..")
                    .because("client/ owns live connection/session state and sits BELOW checks/. The "
                            + "discovery content scan runs on connect through a DiscoveryResultObserver "
                            + "callback (defined in client/), so the scanner in checks/content registers "
                            + "itself as an observer at the composition root rather than client/ reaching "
                            + "up into checks/. client/ must never import a checks type.");

    @ArchTest
    static final ArchRule scan_does_not_depend_on_ui_proxy_or_checks =
            noClasses().that().resideInAPackage("com.mcpscanner.scan..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "com.mcpscanner.checks..",
                            "com.mcpscanner.proxy..",
                            "com.mcpscanner.ui..")
                    .because("scan/ builds Burp insertion points from MCP tool definitions. It legitimately depends "
                            + "on auth.AuthStrategy (interface) to attach credentials to outbound scans, but must not "
                            + "reach into checks/proxy/ui — those are consumers of scan output.");

    @ArchTest
    static final ArchRule proxy_does_not_depend_on_ui_or_checks =
            noClasses().that().resideInAPackage("com.mcpscanner.proxy..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "com.mcpscanner.checks..",
                            "com.mcpscanner.ui..")
                    .because("proxy/ is a thin HTTP/SSE filter wrapping McpScannerSession. It must stay "
                            + "decoupled from check logic and the UI; protocol utilities live in mcp/.");
}
