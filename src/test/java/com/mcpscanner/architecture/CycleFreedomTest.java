package com.mcpscanner.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.DoNotIncludeTests.class)
public class CycleFreedomTest {

    @ArchTest
    static final ArchRule ui_subpackages_are_free_of_cycles =
            slices().matching("com.mcpscanner.ui.(*)..")
                    .should().beFreeOfCycles()
                    .because("Inside ui/: state/, widgets/, and the panel layer must form a DAG. The reducer "
                            + "(ui/state/) emits actions consumed by panels, and widgets are leaf reusables — "
                            + "if any cycle appeared we would have lost the testability win of separating "
                            + "presentation from state.");

    @ArchTest
    static final ArchRule auth_subpackages_are_free_of_cycles =
            slices().matching("com.mcpscanner.auth.(*)..")
                    .should().beFreeOfCycles()
                    .because("Inside auth/: oauth/ and oauth/discovery/ must form a DAG. Discovery emits "
                            + "metadata consumed by the OAuth flow; the flow must not call back into discovery.");

    @ArchTest
    static final ArchRule checks_subpackages_are_free_of_cycles =
            slices().matching("com.mcpscanner.checks.(*)..")
                    .should().beFreeOfCycles()
                    .because("Inside checks/: registry/ holds the catalogue and toggle metadata; content/ "
                            + "consumes ScanCheckSettings from registry/ to honour toggles. ContentRuleDescriptor "
                            + "lives in registry/ so registry/ never has to import content/ back.");

    @ArchTest
    static final ArchRule top_level_packages_are_free_of_cycles =
            slices().matching("com.mcpscanner.(*)..")
                    .should().beFreeOfCycles()
                    .because("HeaderMutation and the MCP protocol data records moved to mcp/, "
                            + "removing the auth<->checks cycle (via HeaderMutation) and the client<->checks cycle "
                            + "(via the data-record back-references in DiscoveredContent/IconContentRule/etc.). "
                            + "The former client->checks edge (McpClientManager constructing DiscoveryContentScanner) "
                            + "is now inverted via DiscoveryResultObserver; see "
                            + "LayeringTest.client_does_not_depend_on_checks.");
}
