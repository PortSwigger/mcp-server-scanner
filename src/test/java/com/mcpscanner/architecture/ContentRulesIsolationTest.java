package com.mcpscanner.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.DoNotIncludeTests.class)
public class ContentRulesIsolationTest {

    @ArchTest
    static final ArchRule content_rules_do_not_depend_on_burp_runtime =
            noClasses().that().resideInAPackage("com.mcpscanner.checks.content.rules..")
                    .should().dependOnClassesThat().haveFullyQualifiedName("burp.api.montoya.MontoyaApi")
                    .orShould().dependOnClassesThat().resideInAnyPackage(
                            "burp.api.montoya.http.message..",
                            "burp.api.montoya.logging..",
                            "burp.api.montoya.scanner.audit",
                            "burp.api.montoya.scanner.audit.insertionpoint..",
                            "burp.api.montoya.persistence..")
                    .because("Content rules evaluate text and must remain unit-testable without a Burp "
                            + "runtime. Severity/confidence enums and HttpService (a metadata holder) are "
                            + "fine — Montoya runtime types (MontoyaApi, HttpRequest, AuditIssue builder, "
                            + "Logging, Persistence) are not. Reaching for those would force a rule's tests "
                            + "to stand up Burp stubs to exercise pure text matching.");

    @ArchTest
    static final ArchRule content_rules_do_not_depend_on_runtime_packages =
            noClasses().that().resideInAPackage("com.mcpscanner.checks.content.rules..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "com.mcpscanner.checks.registry..",
                            "com.mcpscanner.config..",
                            "com.mcpscanner.logging..",
                            "com.mcpscanner.proxy..",
                            "com.mcpscanner.scan..",
                            "com.mcpscanner.ui..")
                    .because("Content rules are pure text evaluators of MCP discovery data. They may reach "
                            + "checks/content/ (the ContentRule contract + DiscoveredContent + Violation), "
                            + "client/ (the MCP definition records they walk), and auth/oauth/OAuthUrlValidator "
                            + "(URL classification shared with PrivateIpRule). Reaching into registry/, config/, "
                            + "proxy/, or ui/ would couple a rule to runtime state or UI presentation.");
}
