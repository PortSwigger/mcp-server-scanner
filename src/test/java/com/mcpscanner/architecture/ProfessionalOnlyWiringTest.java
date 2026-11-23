package com.mcpscanner.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.EvaluationResult;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProfessionalOnlyWiringTest {

    private static final String PRODUCTION_WIRING = "com.mcpscanner";
    private static final String COMMUNITY_LEAK = "com.mcpscanner.architecture.prowiring.communityleak";
    private static final String PROFESSIONAL_ONLY = "com.mcpscanner.architecture.prowiring.professionalonly";

    private static final JavaClasses PRODUCTION_CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages(PRODUCTION_WIRING);
    private static final JavaClasses FIXTURE_CLASSES = new ClassFileImporter()
            .importPackages(COMMUNITY_LEAK, PROFESSIONAL_ONLY);

    @Test
    void onlyProfessionalWiringReachesProfessionalOnlyParts() {
        ProfessionalOnlyWiringRules.onlyProfessionalWiringReachesProfessionalOnlyParts(PRODUCTION_WIRING)
                .check(PRODUCTION_CLASSES);
    }

    @Test
    void entryPointReachesProfessionalOnlyPartsOnlyFromItsProfessionalMethods() {
        ProfessionalOnlyWiringRules.entryPointReachesProfessionalOnlyPartsOnlyFromItsProfessionalMethods(
                PRODUCTION_WIRING).check(PRODUCTION_CLASSES);
    }

    @Test
    void entryPointBuildsProfessionalWiringOnlyThroughTheGate() {
        ProfessionalOnlyWiringRules.entryPointBuildsProfessionalWiringOnlyThroughTheGate(PRODUCTION_WIRING)
                .check(PRODUCTION_CLASSES);
    }

    @Test
    void professionalFeaturesAreBuiltOnlyWhenScanningIsAvailable() {
        ProfessionalOnlyWiringRules.professionalFeaturesAreBuiltOnlyWhenScanningIsAvailable(PRODUCTION_WIRING)
                .check(PRODUCTION_CLASSES);
    }

    @Test
    void communityWiringNeverNamesProfessionalWiring() {
        ProfessionalOnlyWiringRules.communityWiringNeverNamesProfessionalWiring(PRODUCTION_WIRING)
                .check(PRODUCTION_CLASSES);
    }

    @Test
    void aWiringClassCallingTheScannerIsReportedAsAViolation() {
        assertThat(violations(ProfessionalOnlyWiringRules
                .onlyProfessionalWiringReachesProfessionalOnlyParts(COMMUNITY_LEAK)))
                .contains("ConnectionWiring.scanner(")
                .contains("MontoyaApi.scanner()");
    }

    @Test
    void aCommunityMethodOfTheEntryPointReachingCollaboratorIsReportedAsAViolation() {
        assertThat(violations(ProfessionalOnlyWiringRules
                .entryPointReachesProfessionalOnlyPartsOnlyFromItsProfessionalMethods(COMMUNITY_LEAK)))
                .contains("McpScannerExtension.initialize(")
                .contains("MontoyaApi.collaborator()");
    }

    @Test
    void communityWiringNamingProfessionalWiringIsReportedAsAViolation() {
        assertThat(violations(ProfessionalOnlyWiringRules.communityWiringNeverNamesProfessionalWiring(COMMUNITY_LEAK)))
                .contains("IdentityWiring")
                .contains("ScanningWiring");
    }

    @Test
    void theEntryPointBuildingProfessionalWiringOutsideTheGateIsReportedAsAViolation() {
        assertThat(violations(ProfessionalOnlyWiringRules
                .entryPointBuildsProfessionalWiringOnlyThroughTheGate(COMMUNITY_LEAK)))
                .contains("McpScannerExtension.discovery()")
                .contains("IdentityDiscoveryWiring.create()")
                .contains("McpScannerExtension.features()")
                .contains("ProfessionalFeatures.<init>()");
    }

    @Test
    void aGateThatDoesNotAskTheEditionIsReportedAsAViolation() {
        assertThat(violations(ProfessionalOnlyWiringRules
                .professionalFeaturesAreBuiltOnlyWhenScanningIsAvailable(COMMUNITY_LEAK)))
                .contains("ProfessionalFeatures.createIfScanningAvailable()")
                .contains("does not call");
    }

    @Test
    void theEntryPointMayBuildProfessionalWiringThroughTheGateThatAsksTheEdition() {
        assertThat(ProfessionalOnlyWiringRules.entryPointBuildsProfessionalWiringOnlyThroughTheGate(PROFESSIONAL_ONLY)
                .evaluate(FIXTURE_CLASSES).hasViolation()).isFalse();
        assertThat(ProfessionalOnlyWiringRules
                .professionalFeaturesAreBuiltOnlyWhenScanningIsAvailable(PROFESSIONAL_ONLY)
                .evaluate(FIXTURE_CLASSES).hasViolation()).isFalse();
    }

    @Test
    void professionalWiringAndTheEntryPointsProfessionalMethodsMayReachProfessionalOnlyParts() {
        assertThat(ProfessionalOnlyWiringRules.onlyProfessionalWiringReachesProfessionalOnlyParts(PROFESSIONAL_ONLY)
                .evaluate(FIXTURE_CLASSES).hasViolation()).isFalse();
        assertThat(ProfessionalOnlyWiringRules
                .entryPointReachesProfessionalOnlyPartsOnlyFromItsProfessionalMethods(PROFESSIONAL_ONLY)
                .evaluate(FIXTURE_CLASSES).hasViolation()).isFalse();
        assertThat(ProfessionalOnlyWiringRules.communityWiringNeverNamesProfessionalWiring(PROFESSIONAL_ONLY)
                .evaluate(FIXTURE_CLASSES).hasViolation()).isFalse();
    }

    private static String violations(ArchRule rule) {
        EvaluationResult result = rule.evaluate(FIXTURE_CLASSES);
        assertThat(result.hasViolation()).isTrue();
        return String.join("\n", result.getFailureReport().getDetails());
    }
}
