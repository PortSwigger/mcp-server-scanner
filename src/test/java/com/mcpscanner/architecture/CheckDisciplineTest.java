package com.mcpscanner.architecture;

import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ManagedActiveCheck;
import com.mcpscanner.checks.registry.ManagedPassiveCheck;
import com.mcpscanner.checks.registry.ManagedScanStartCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.DoNotIncludeTests.class)
public class CheckDisciplineTest {

    @ArchTest
    static final ArchRule concrete_active_scan_checks_extend_managed_active_check =
            classes().that().areAssignableTo(ActiveScanCheck.class)
                    .and().resideInAPackage("com.mcpscanner..")
                    .and().areNotInterfaces()
                    .and().doNotHaveModifier(JavaModifier.ABSTRACT)
                    .should().beAssignableTo(ManagedActiveCheck.class)
                    .because("Every concrete Burp ActiveScanCheck must route through ManagedActiveCheck so the "
                            + "Scan Checks UI toggle and CheckDescriptor metadata cannot be bypassed. A bare "
                            + "implements ActiveScanCheck would silently always run and expose no descriptor.");

    @ArchTest
    static final ArchRule concrete_passive_scan_checks_extend_managed_passive_check =
            classes().that().areAssignableTo(PassiveScanCheck.class)
                    .and().resideInAPackage("com.mcpscanner..")
                    .and().areNotInterfaces()
                    .and().doNotHaveModifier(JavaModifier.ABSTRACT)
                    .should().beAssignableTo(ManagedPassiveCheck.class)
                    .because("Every concrete Burp PassiveScanCheck must route through ManagedPassiveCheck for "
                            + "the same toggle/descriptor reasons as the active variant. DiscoveryContentScanner "
                            + "is intentionally NOT a PassiveScanCheck — it runs at MCP discovery time, not on "
                            + "passive HTTP traffic, so it does not trigger this rule.");

    @ArchTest
    static final ArchRule managed_checks_declare_a_descriptor_field =
            classes().that().areAssignableTo(ManagedActiveCheck.class)
                    .or().areAssignableTo(ManagedPassiveCheck.class)
                    .or().areAssignableTo(ManagedScanStartCheck.class)
                    .and().resideInAPackage("com.mcpscanner..")
                    .and().areNotInterfaces()
                    .and().doNotHaveModifier(JavaModifier.ABSTRACT)
                    .should(declareStaticFinalDescriptorField())
                    .because("ManagedCheck subclasses surface their toggle metadata via a static final "
                            + "CheckDescriptor DESCRIPTOR field that descriptor() returns. Omitting the "
                            + "field leaves the toggle-key derivation NPE-prone at registration time — "
                            + "catch the gap here.");

    @ArchTest
    static final ArchRule managed_checks_accept_scan_check_settings_first =
            classes().that().areAssignableTo(ManagedActiveCheck.class)
                    .or().areAssignableTo(ManagedPassiveCheck.class)
                    .or().areAssignableTo(ManagedScanStartCheck.class)
                    .and().resideInAPackage("com.mcpscanner..")
                    .and().areNotInterfaces()
                    .and().doNotHaveModifier(JavaModifier.ABSTRACT)
                    .should(declareConstructorWithSettingsFirst())
                    .because("ManagedActiveCheck/ManagedPassiveCheck base classes require a ScanCheckSettings "
                            + "to honour the per-check UI toggle. Subclasses pass it through their first "
                            + "constructor parameter — a different shape (no-arg constructor, or settings "
                            + "later in the list) silently disables the toggle plumbing.");

    private static ArchCondition<JavaClass> declareStaticFinalDescriptorField() {
        return new ArchCondition<>("declare a static final CheckDescriptor DESCRIPTOR field") {
            @Override
            public void check(JavaClass clazz, ConditionEvents events) {
                boolean ok = clazz.getFields().stream().anyMatch(field ->
                        "DESCRIPTOR".equals(field.getName())
                                && field.getModifiers().contains(JavaModifier.STATIC)
                                && field.getModifiers().contains(JavaModifier.FINAL)
                                && CheckDescriptor.class.getName().equals(field.getRawType().getName()));
                if (!ok) {
                    events.add(SimpleConditionEvent.violated(clazz,
                            clazz.getName() + " has no static final CheckDescriptor DESCRIPTOR field"));
                }
            }
        };
    }

    private static ArchCondition<JavaClass> declareConstructorWithSettingsFirst() {
        return new ArchCondition<>("declare a constructor whose first parameter is ScanCheckSettings") {
            @Override
            public void check(JavaClass clazz, ConditionEvents events) {
                boolean ok = clazz.getConstructors().stream().anyMatch(ctor -> {
                    var params = ctor.getRawParameterTypes();
                    return !params.isEmpty()
                            && ScanCheckSettings.class.getName().equals(params.get(0).getName());
                });
                if (!ok) {
                    events.add(SimpleConditionEvent.violated(clazz,
                            clazz.getName() + " has no constructor whose first parameter is ScanCheckSettings"));
                }
            }
        };
    }
}
