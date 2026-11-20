package com.mcpscanner.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.DoNotIncludeTests.class)
public class DeletedTypesTest {

    @ArchTest
    static final ArchRule json_schema_converter_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.client.JsonSchemaConverter")
                    .because("Deleted in Wave 2. The langchain4j JsonSchemaElement -> Map bridge now lives in "
                            + "LangchainSchemaTranslator, extracted from McpDiscoveryClient as its single owner. "
                            + "Reintroducing JsonSchemaConverter would resurrect a parallel schema-conversion code "
                            + "path beside it.");

    @ArchTest
    static final ArchRule streamable_http_session_manager_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.client.StreamableHttpSessionManager")
                    .because("Deleted during the session-state consolidation: handshake + Mcp-Session-Id "
                            + "negotiation now lives directly on McpScannerSession. A separate manager would "
                            + "split session ownership back into two places.");

    @ArchTest
    static final ArchRule registered_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.registry.RegisteredCheck")
                    .because("Replaced by CheckDescriptor + ManagedCheck. The old RegisteredCheck record paired "
                            + "metadata with a check instance externally; the new design makes the check itself "
                            + "the source of its descriptor (ManagedCheck.descriptor()).");

    @ArchTest
    static final ArchRule toggleable_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.registry.ToggleableCheck")
                    .because("Replaced by ManagedActiveCheck/ManagedPassiveCheck base classes that gate execution "
                            + "via descriptor()+settings, eliminating the decorator layer entirely.");

    @ArchTest
    static final ArchRule toggleable_scan_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.registry.ToggleableScanCheck")
                    .because("Replaced by ManagedActiveCheck — the active scan toggle now lives inline in the "
                            + "base class instead of in a wrapping decorator.");

    @ArchTest
    static final ArchRule toggleable_passive_scan_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.registry.ToggleablePassiveScanCheck")
                    .because("Replaced by ManagedPassiveCheck — same reasoning as the active variant.");

    @ArchTest
    static final ArchRule no_toggleable_classes_anywhere =
            noClasses().should().haveSimpleNameStartingWith("Toggleable")
                    .because("The Toggleable* decorator family was removed by the registry refactor. A new class "
                            + "starting with `Toggleable` is a strong signal that someone is adding a check "
                            + "outside the ManagedActiveCheck/ManagedPassiveCheck pattern.");

    @ArchTest
    static final ArchRule mcp_request_detector_must_not_return_to_checks_package =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpRequestDetector")
                    .because("Moved to com.mcpscanner.mcp in Wave 15 to break a checks/ <-> mcp/ dependency "
                            + "cycle. Re-creating it under checks/ would shadow the canonical detector and "
                            + "re-establish the cycle the move was meant to eliminate.");

    @ArchTest
    static final ArchRule stub_passive_scan_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.registry.StubPassiveScanCheck")
                    .because("Replaced by JsonRpcDiscoveryResponseScanner in T8: the master discovery "
                            + "content scanner toggle now drives a real ManagedPassiveCheck that inspects "
                            + "tools/list / resources/list / prompts/list / initialize JSON-RPC response "
                            + "bodies. Re-introducing a no-op stub would silently re-orphan the toggle "
                            + "from any wire-traffic emission path.");

    @ArchTest
    static final ArchRule tool_enum_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveToolEnumCheck")
                    .because("Merged into McpActiveUnauthenticatedToolDiscoveryCheck (itself replaced by the catalog "
                            + "unauthenticated-request-execution check): tool-enum and "
                            + "no-auth-exposure detected the same unauthenticated tools/list exposure with "
                            + "inverse firing guards (auth-present vs auth-absent) and a duplicated oracle. "
                            + "Re-introducing it would resurrect the confusingly-named duplicate the merge removed.");

    @ArchTest
    static final ArchRule no_auth_exposure_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveNoAuthExposureCheck")
                    .because("Merged into McpActiveUnauthenticatedToolDiscoveryCheck (itself replaced by the catalog "
                            + "unauthenticated-request-execution check) alongside the former "
                            + "tool-enum check — the single check branches on whether auth was present rather "
                            + "than splitting the same detection across two inverse-guarded checks.");

    @ArchTest
    static final ArchRule rule_catalogue_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.registry.RuleCatalogue")
                    .because("Introduced in b1a9319 to break a content <-> registry cycle, then orphaned when "
                            + "ScanCheckRegistry was refactored to instantiate rules via ContentRules.all(). "
                            + "Re-introducing it would resurrect a second, divergent source of the default "
                            + "ContentRuleDescriptor catalogue.");

    @ArchTest
    static final ArchRule checks_dropped_from_the_catalog_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.JsonRpcDiscoveryResponseScanner")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.JsonRpcResponseContentScanner")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.content.DiscoveryContentScanner")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveOAuthMetadataSsrfCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.issue.OAuthMetadataConsistencyReporter")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.auth.oauth.OAuthMetadataConsistencyListener")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveHiddenMethodCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.HiddenMethodWordlist")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.registry.ManagedPassiveCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveDcrMisconfigurationCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.DcrRedirectUriProbe")
                    .because("The check reselection dropped the passive content scanners, OAuth "
                            + "metadata SSRF, OAuth metadata consistency reporting and hidden JSON-RPC method "
                            + "probing. The legacy DCR misconfiguration check is replaced by the oauth-redirect-policy catalog check, whose same-client controls stop it reporting a hostile registration as account takeover. Outbound fetches of OAuth metadata URLs are folded into the outbound-request "
                            + "check instead; reintroducing these would resurrect findings the decision record rejected.");

    @ArchTest
    static final ArchRule legacy_tool_argument_rce_check_stays_deleted =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveToolArgumentRceCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ToolsCallRceProbeRunner")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ToolArgRcePayloads")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.CollaboratorPoller")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.RceIssueReporter")
                    .because("Replaced by the command-injection catalog check, which probes every MCP field with "
                            + "controlled shell, interpreter and Collaborator payloads. The legacy check only sent "
                            + "uncontrolled Collaborator payloads to selected tool arguments.");

    @ArchTest
    static final ArchRule discovery_passive_audit_bridge_stays_deleted =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.client.McpDiscoveryAuditBridge")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.client.CapturedExchange")
                    .because("Removed with the generator rebuild: no extension passive check consumes "
                            + "discovery traffic any more, so the per-connect passive audit only added a Dashboard "
                            + "task per connection.");

    @ArchTest
    static final ArchRule per_kind_locators_stay_replaced_by_the_generic_json_locator =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.scan.ArgumentsObjectLocator")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.scan.ArgumentValueLocator")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.scan.UriValueLocator")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.scan.JsonRpcRequestBuilder")
                    .because("The field generator walks every value under params recursively "
                            + "(mcp.JsonLeafLocator) and the request generator renders every request family "
                            + "(scan.request); per-kind locators only covered top-level tool and prompt arguments "
                            + "and the resource URI.");

    @ArchTest
    static final ArchRule legacy_jwt_validation_replaced_by_the_catalog_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveOAuthTokenValidationCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.OAuthJwtProbeFactory")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.JwtShapeDetector")
                    .because("The catalog check checks.catalog.jwtvalidation replaced the legacy OAuth token "
                            + "validation check; two JWT checks would double-report every forged-token finding.");

    @ArchTest
    static final ArchRule command_injection_collaborator_copies_must_not_return =
            noClasses().should().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.commandinjection.OutOfBandLedger")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.catalog.commandinjection.Pause")
                    .because("Command injection's Collaborator confirmations run on the shared "
                            + "checks.shared.collaborator.CollaboratorWatch, which owns the lazy client, polling, "
                            + "payload routing and the re-delivered interaction dedupe. A check-local ledger would "
                            + "miss fixes made to the shared one.");

    @ArchTest
    static final ArchRule blocking_collaborator_waits_must_not_return =
            noClasses().should().haveFullyQualifiedName(
                            "com.mcpscanner.checks.shared.collaborator.DeferredConfirmations")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.shared.collaborator.Confirmation")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.shared.collaborator.PendingConfirmation")
                    .because("Checks no longer wait for Collaborator: they register their probes with the shared "
                            + "CollaboratorWatch and return, and the watch reports late issues through "
                            + "CheckServices.lateIssues(). A scan thread sleeping on a settle window per field "
                            + "made a full scan take over half an hour.");

    @ArchTest
    static final ArchRule jwt_validation_metadata_fetchers_must_not_return =
            noClasses().should().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.jwtvalidation.HttpJsonDocumentFetcher")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.jwtvalidation.JsonDocumentFetcher")
                    .because("JWT key discovery reads metadata through checks.shared.oauth: WellKnownLocations, "
                            + "AuthorizationServerMetadataFetcher, OAuthHttp (which stops an audit on HTTP 429) "
                            + "and JsonDocument. A check-local fetcher would bypass the shared locations and "
                            + "rate-limit stop.");

    @ArchTest
    static final ArchRule consent_page_reflected_xss_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveConsentPageReflectedXssCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ConsentReflectionAnalyzer")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ConsentUrlResolver")
                    .because("Replaced by the oauth-consent-structure-reflection catalog check (check "
                            + "reselection): it rated a string-search reflection HIGH/FIRM XSS. The rewrite "
                            + "reports only parsed HTML structure at INFORMATION/TENTATIVE and never claims "
                            + "script execution.");

    @ArchTest
    static final ArchRule legacy_dns_rebinding_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveDnsRebindingCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.DnsRebindingProbe")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.HostReachability")
                    .because("Replaced by the origin-host-admission catalog check. The legacy "
                            + "check sent its Host probes through the local proxy, which drops the Host header, "
                            + "and HostReachability now lives in checks.shared.net.");

    @ArchTest
    static final ArchRule legacy_checks_replaced_by_unauthenticated_request_execution_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveAuthBypassCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveUnauthenticatedToolDiscoveryCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.AuthProbeRunner")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.AuthProbes")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.AuthProbe")
                    .because("Replaced by the catalog unauthenticated-request-execution check, which accepts any "
                            + "MCP method, reports the open catalog as information and uses the shared auth-variant "
                            + "module and default oracle; a second auth-bypass path would duplicate its findings.");

    @ArchTest
    static final ArchRule legacy_traversal_checks_stay_replaced_by_the_file_traversal_catalog_check =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveResourcePathTraversalCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveToolArgumentPathTraversalCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ToolsCallTraversalProbeRunner")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ResourcesReadProbeRunner")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.scan.PathArgumentHeuristic")
                    .because("Replaced by checks.catalog.filetraversal: one insertion-point check covers every MCP "
                            + "field with matched missing-file controls, instead of two self-discovering request "
                            + "checks limited to path-named tool arguments and resource URIs.");

    @ArchTest
    static final ArchRule legacy_scan_start_seam_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.LegacyChecks")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.scan.ScanStartCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.scan.ScanStartContext")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.scan.CurrentSelectionHolder")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.registry.ManagedScanStartCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.registry.ManagedActiveCheck")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.registry.SessionScopedCheck")
                    .because("Every check is a catalog McpCheck adapted by kind. The empty legacy suite, the "
                            + "scan-start hook it fed and the extra registry base class existed only for "
                            + "pre-catalog checks; ConnectionScoped is the one disconnect-reset concept.");

    @ArchTest
    static final ArchRule orphaned_pre_catalog_helpers_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.ProbeBaseline")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ReachabilityTrackingHttp")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.HostDedup")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.SelectedToolsFilter")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.SessionBaselineFactory")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ToolArgumentFinder")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ToolArgument")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ArgumentHeuristic")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ToolsCallBodyBuilder")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.ToolsListDiscovery")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.scan.CodeArgumentHeuristic")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.JsonRpcBody")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.McpReplyGates")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.ReplyShapeSignature")
                    .because("Pre-catalog probe helpers with no production caller. Checks build requests "
                            + "through scan/request and checks/shared, and JsonRpcBody hand-escaped JSON. The "
                            + "McpReplyGates response gates served only those helpers; reply parsing belongs "
                            + "in checks/shared.");

    @ArchTest
    static final ArchRule orphaned_origin_response_classifiers_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.mcp.DiscoveryResponseShapes")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.ResponseShapeSignature")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.JsonRpcResponseClassifier")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.JsonRpcBodyBuilder")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.McpRequestDetector$DiscoveryResponseKind")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.McpRequestDetector$ResponseContentKind")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.scan.JsonSchemaPredicates")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.auth.oauth.discovery.BurpAuthorizationServerDiscovery")
                    .because("Their only callers were the checks the reselection removed. Reply parsing lives in "
                            + "checks/shared/jsonrpc and probe-side authorization-server discovery in "
                            + "checks/shared/oauth, so a second copy here would read as live API beside them.");

    @ArchTest
    static final ArchRule protocol_framing_lives_only_in_the_shared_runtime =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.mcp.McpHandshake")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.McpProtocolVersions")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.McpRequestEnvelope")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.McpWireAlignment")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.McpHeaderValue")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.McpRoutingName")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.SessionNotFound")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.mcp.McpResponseBody")
                    .because("Handshakes, protocol versions, the stateless envelope and routing headers come from "
                            + "the shared MCP protocol core through McpScannerSession and McpOperationFraming; a "
                            + "second copy beside it drifts from what the connection actually negotiated.");

    @ArchTest
    static final ArchRule json_rpc_parsing_copies_stay_in_the_shared_toolkit =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.shared.auth.oracle.JsonRpcRequest")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.shared.auth.oracle.JsonRpcMessages")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.shared.auth.oracle.JsonNodes")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.catalog.outboundrequest.JsonBodies")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.catalog.commandinjection.McpReply")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.catalog.filetraversal.McpReply")
                    .because("JSON-RPC request and reply parsing lives once in checks/shared/jsonrpc: "
                            + "JsonRpcEnvelope parses a request body, McpReply reads a reply and JsonRpcMessages "
                            + "unwraps SSE through mcp/SseResponseParser. Checks keep only their own predicates on "
                            + "top, so a per-check parser would bring back the drift the toolkit removed.");

    @ArchTest
    static final ArchRule issue_identity_copies_stay_in_the_shared_issue_package =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.catalog.filetraversal.IssueLocation")
                    .because("Whether two issues report the same subject is decided once by "
                            + "checks.issue.IssueIdentity, so every check that consolidates by its first detail "
                            + "paragraph agrees on what that paragraph is and on how a missing detail is treated.");

    @ArchTest
    static final ArchRule issue_rating_copies_stay_in_the_shared_issue_package =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.catalog.outboundrequest.Rating")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.unauthenticatedrequestexecution.Rating")
                    .because("A severity and confidence pair is checks.issue.IssueRating, shared by every check "
                            + "that rates its own findings.");

    @ArchTest
    static final ArchRule catalog_checks_keep_one_name_per_role =
            noClasses().should().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.commandinjection.IssueRenderer")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.commandinjection.ProbeResult")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.filetraversal.TraversalIssues")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.filetraversal.FindingType")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.filetraversal.ProbeResult")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.jwtvalidation.ForgedTokenIssue")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.oauthconsentstructurereflection.ConsentStructureIssues")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.oauthredirectpolicy.IssueAssembler")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.oauthredirectpolicy.FindingType")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.oauthrefreshgrant.RefreshIssueFactory")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.originhostadmission.AdmissionIssues")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.outboundrequest.OutboundIssues")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.downstreamrouteescape.RouteEscapeIssues")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.unauthenticatedrequestexecution.IssueRenderer")
                    .because("Each check turns findings into AuditIssues in <Check>Issues and classifies them "
                            + "with FindingKind. ProbeResult meant different things in two checks, so command "
                            + "injection's is ProbeOutcome and file traversal's is TraversalAttempt.");

    @ArchTest
    static final ArchRule checks_root_package_holds_no_classes =
            noClasses().should().resideInAPackage("com.mcpscanner.checks")
                    .because("The checks root holds only the api, catalog, issue, registry and shared packages.");

    @ArchTest
    static final ArchRule the_primary_identity_model_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.identity.credentials.PrimarySwap")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.identity.PrimaryProfile")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.identity.credentials.PrimaryAuthentication")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.identity.credentials.PrimaryAuthSettings")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.identity.credentials.PrimaryAuthKind")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.identity.credentials.OAuthClientMemory")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.ui.identities.PrimaryProfileEditor")
                    .because("Every user, the one Connect runs as included, is an Identity in IdentityRegistry, "
                            + "and IdentityRegistry.connectAs chooses which. A separate primary profile or a swap "
                            + "between Authentication and Identities splits the user list back into two places.");

    @ArchTest
    static final ArchRule the_cross_identity_scan_check_must_not_return =
            noClasses().should().resideInAPackage("com.mcpscanner.checks.catalog.crossidentityaccess..")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.checks.api.AccessComparison")
                    .orShould().haveFullyQualifiedName("com.mcpscanner.access.comparison.CrossIdentityRun")
                    .because("Cross-identity testing is the Access engine (access.comparison), run only by Check "
                            + "access over each user's entered and mined values. A catalog check would replay "
                            + "captured traffic as other users from Burp scans again, outside the Access tab's "
                            + "ratings, ledger and write-replay confirmation.");

    @ArchTest
    static final ArchRule per_check_host_claims_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.shared.host.ClaimedHosts")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.crossclientresponseleak.HostClaim")
                    .because("Checks that probe each host until a conclusive trial are HOST checks with "
                            + "HostTrials; HostAudits owns the per-host claims and retry limits for every one.");

    @ArchTest
    static final ArchRule issue_evidence_redaction_must_not_return =
            noClasses().that().resideOutsideOfPackages("com.mcpscanner.logging..", "com.mcpscanner.ui..")
                    .should().haveSimpleNameContaining("Redact")
                    .orShould().haveSimpleNameContaining("Scrub")
                    .orShould().haveSimpleNameContaining("Masker")
                    .orShould().haveFullyQualifiedName(
                            "com.mcpscanner.checks.catalog.oauthrefreshgrant.SecretRecordingGrant")
                    .because("Issue evidence is always the raw exchange: a tester reproduces a finding by sending "
                            + "its evidence to Repeater, which masked credentials or tokens would break. Log "
                            + "redaction lives in logging.LogRedaction and never touches issue evidence.");
}
