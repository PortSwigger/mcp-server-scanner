package com.mcpscanner.architecture;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaCodeUnit;
import com.tngtech.archunit.lang.ArchRule;

import java.util.Set;
import java.util.stream.Collectors;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.codeUnits;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noCodeUnits;

final class ProfessionalOnlyWiringRules {

    private static final String ENTRY_POINT = "McpScannerExtension";
    private static final String GATE_OWNER = "ProfessionalFeatures";
    private static final String GATE = "createIfScanningAvailable";
    private static final String EDITION = "BurpEdition";
    private static final String EDITION_CHECK = "scanningAvailable";

    private static final Set<String> PROFESSIONAL_WIRING = Set.of(
            "ProfessionalFeatures", "ScanFoundation", "ScanningWiring", "AccessWiring", "MiningWiring",
            "EngineWiring", "EngineInstrumentation", "ScanFieldWiring", "RegistrationCleanupWiring",
            "IdentityDiscoveryWiring", "TestAutomationWiring", "SignedInConsentWiring");

    private static final Set<String> COMMUNITY_WIRING = Set.of(
            "ExtensionFoundation", "ConnectionWiring", "OAuthWiring", "IdentityWiring", "RequestBuildingWiring");

    private static final Set<String> ENTRY_POINT_PROFESSIONAL_METHODS = Set.of(
            "installProfessionalUi", "mcpOnlyScanMenu", "accessServices", "miningServices", "scansServices",
            "scanServices");

    private ProfessionalOnlyWiringRules() {
    }

    static ArchRule onlyProfessionalWiringReachesProfessionalOnlyParts(String wiringPackage) {
        return noClasses().that().resideInAPackage(wiringPackage)
                .and(namedIn(wiringPackage, PROFESSIONAL_WIRING).negate())
                .and().doNotHaveFullyQualifiedName(qualified(wiringPackage, ENTRY_POINT))
                .should(ProfessionalOnlyParts.reachedByClass())
                .allowEmptyShould(true)
                .because("Burp Suite Community has no scanner, Collaborator or site map, so scanning, Check access, "
                        + "Collect IDs and compared-user discovery are built only by the Professional wiring");
    }

    static ArchRule entryPointReachesProfessionalOnlyPartsOnlyFromItsProfessionalMethods(String wiringPackage) {
        return noCodeUnits().that().areDeclaredInClassesThat()
                .haveFullyQualifiedName(qualified(wiringPackage, ENTRY_POINT))
                .and(DescribedPredicate.describe("are not its Professional UI methods",
                        (JavaCodeUnit codeUnit) -> !ENTRY_POINT_PROFESSIONAL_METHODS.contains(codeUnit.getName())))
                .should(ProfessionalOnlyParts.reachedByCodeUnit())
                .allowEmptyShould(true)
                .because("the entry point assembles the Professional UI only in methods run when Burp is "
                        + "Professional; the rest of it runs in every edition");
    }

    static ArchRule entryPointBuildsProfessionalWiringOnlyThroughTheGate(String wiringPackage) {
        return noCodeUnits().that().areDeclaredInClassesThat()
                .haveFullyQualifiedName(qualified(wiringPackage, ENTRY_POINT))
                .and(DescribedPredicate.describe("are not its Professional UI methods or their lambdas",
                        (JavaCodeUnit codeUnit) -> !isProfessionalMethodOrItsLambda(codeUnit.getName())))
                .should(ProfessionalWiringNames.otherThanThroughTheGate(
                        qualified(wiringPackage, GATE_OWNER), GATE, namedIn(wiringPackage, PROFESSIONAL_WIRING)))
                .allowEmptyShould(true)
                .because("the entry point runs in every edition, so it builds the Professional wiring only through "
                        + GATE_OWNER + "." + GATE + " and otherwise reaches it only through ProfessionalFeatures");
    }

    static ArchRule professionalFeaturesAreBuiltOnlyWhenScanningIsAvailable(String wiringPackage) {
        return codeUnits().that().areDeclaredInClassesThat()
                .haveFullyQualifiedName(qualified(wiringPackage, GATE_OWNER))
                .and().haveName(GATE)
                .should(ProfessionalWiringNames.call(qualified(wiringPackage, EDITION), EDITION_CHECK))
                .because("the gated entry builds the Professional wiring only when Burp is Professional");
    }

    static ArchRule communityWiringNeverNamesProfessionalWiring(String wiringPackage) {
        return noClasses().that(namedIn(wiringPackage, COMMUNITY_WIRING))
                .should().dependOnClassesThat(namedIn(wiringPackage, PROFESSIONAL_WIRING))
                .orShould(ProfessionalOnlyParts.reachedByClass())
                .allowEmptyShould(true)
                .because("the Community wiring is built in every edition, so it never names the Professional "
                        + "wiring or what it builds");
    }

    private static boolean isProfessionalMethodOrItsLambda(String codeUnitName) {
        return ENTRY_POINT_PROFESSIONAL_METHODS.stream().anyMatch(method ->
                codeUnitName.equals(method) || codeUnitName.startsWith("lambda$" + method + "$"));
    }

    private static DescribedPredicate<JavaClass> namedIn(String wiringPackage, Set<String> simpleNames) {
        Set<String> qualifiedNames = simpleNames.stream()
                .map(name -> qualified(wiringPackage, name))
                .collect(Collectors.toSet());
        return DescribedPredicate.describe("are one of " + simpleNames,
                javaClass -> qualifiedNames.contains(topLevelName(javaClass)));
    }

    private static String topLevelName(JavaClass javaClass) {
        return javaClass.getName().split("\\$")[0];
    }

    private static String qualified(String wiringPackage, String simpleName) {
        return wiringPackage + "." + simpleName;
    }
}
