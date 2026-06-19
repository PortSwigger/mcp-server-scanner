package com.mcpscanner.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.DoNotIncludeTests.class)
public class LoggingHygieneTest {

    @ArchTest
    static final ArchRule no_jul_or_slf4j =
            noClasses().should().dependOnClassesThat().resideInAnyPackage(
                            "java.util.logging..",
                            "org.slf4j..",
                            "org.apache.logging..",
                            "ch.qos.logback..")
                    .because("The extension routes all output through burp.api.montoya.logging.Logging "
                            + "so it appears in Burp's Extender > Output tab. Mixing in JUL, SLF4J, or "
                            + "Log4j would split scanner output across destinations and hide important "
                            + "messages from the user.");

    @ArchTest
    static final ArchRule no_system_out_or_err =
            noClasses().should().accessField(System.class, "out")
                    .orShould().accessField(System.class, "err")
                    .because("System.out/err output bypasses the extension's Logging-based routing and "
                            + "lands in stdout/stderr where the user never sees it. Route through "
                            + "burp.api.montoya.logging.Logging instead.");
}
