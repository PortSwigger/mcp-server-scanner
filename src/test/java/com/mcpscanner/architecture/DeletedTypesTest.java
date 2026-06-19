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
                    .because("Deleted in Wave 2: its langchain4j JsonSchemaElement -> Map bridge was inlined into "
                            + "McpDiscoveryClient. Reintroducing it would resurrect a parallel schema-conversion "
                            + "code path with no clear ownership.");

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
                    .because("Merged into McpActiveUnauthenticatedToolDiscoveryCheck: tool-enum and "
                            + "no-auth-exposure detected the same unauthenticated tools/list exposure with "
                            + "inverse firing guards (auth-present vs auth-absent) and a duplicated oracle. "
                            + "Re-introducing it would resurrect the confusingly-named duplicate the merge removed.");

    @ArchTest
    static final ArchRule no_auth_exposure_check_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.McpActiveNoAuthExposureCheck")
                    .because("Merged into McpActiveUnauthenticatedToolDiscoveryCheck alongside the former "
                            + "tool-enum check — the single check branches on whether auth was present rather "
                            + "than splitting the same detection across two inverse-guarded checks.");

    @ArchTest
    static final ArchRule rule_catalogue_must_not_return =
            noClasses().should().haveFullyQualifiedName("com.mcpscanner.checks.registry.RuleCatalogue")
                    .because("Introduced in b1a9319 to break a content <-> registry cycle, then orphaned when "
                            + "ScanCheckRegistry was refactored to instantiate rules via ContentRules.all(). "
                            + "Re-introducing it would resurrect a second, divergent source of the default "
                            + "ContentRuleDescriptor catalogue.");
}
