package com.mcpscanner.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.DoNotIncludeTests.class)
public class ReducerPurityTest {

    @ArchTest
    static final ArchRule ui_state_is_swing_and_awt_free =
            noClasses().that().resideInAPackage("com.mcpscanner.ui.state..")
                    .should().dependOnClassesThat().resideInAnyPackage("javax.swing..", "java.awt..")
                    .because("ui/state/ is the reducer for connection lifecycle: pure UiAction -> UiConnectionState "
                            + "transitions plus a side-effect list. Importing Swing/AWT would couple the reducer "
                            + "to the EDT and prevent the headless unit tests in UiStateReducerTest from existing.");

    @ArchTest
    static final ArchRule ui_connect_is_swing_and_awt_free =
            noClasses().that().resideInAPackage("com.mcpscanner.ui.connect..")
                    .should().dependOnClassesThat().resideInAnyPackage("javax.swing..", "java.awt..")
                    .because("ui/connect/ is the Swing-free connect orchestrator run off the EDT inside the "
                            + "tab's SwingWorker; a Swing/AWT dependency would couple it to the EDT and break "
                            + "the headless ConnectCoordinatorTest.");

    @ArchTest
    static final ArchRule ui_state_does_not_depend_on_sibling_ui_packages =
            noClasses().that().resideInAPackage("com.mcpscanner.ui.state..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "com.mcpscanner.ui",
                            "com.mcpscanner.ui.widgets..")
                    .because("ui/state/ must remain a pure value layer. Its consumers (panels in ui/, widgets in "
                            + "ui/widgets/) reach in to read state — never the other way around. A dep on a panel "
                            + "or widget class would invert the reducer relationship and bring Swing back in "
                            + "through the side door.");
}
