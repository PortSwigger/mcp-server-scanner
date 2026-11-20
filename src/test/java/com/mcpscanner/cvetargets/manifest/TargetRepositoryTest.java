package com.mcpscanner.cvetargets.manifest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TargetRepositoryTest {

    private static final Path PORTED_TARGETS = Path.of("cve-targets");

    @TempDir
    Path root;

    @Test
    void loadsTwoMateriallyDifferentPortedTargets() {
        List<LoadedTarget> targets = new TargetRepository(PORTED_TARGETS).load(TargetSelection.everything());

        assertThat(targets.stream().map(target -> target.manifest().check()).distinct()).hasSizeGreaterThanOrEqualTo(2);
        assertThat(targets).extracting(target -> target.manifest().auth().scheme())
                .contains(AuthScheme.NONE, AuthScheme.BEARER);
        assertThat(targets).filteredOn(target -> !target.manifest().benign()).allSatisfy(target -> assertThat(target.manifest().arms())
                .extracting(TargetArm::role).contains(ArmRole.VULNERABLE, ArmRole.FIXED));
    }

    @Test
    void discoversATargetFromItsDirectoryAndManifestAlone() {
        ManifestFixtures.writeValidTarget(root, "brand-new-check", "brand-new-target");

        List<LoadedTarget> targets = new TargetRepository(root).load(TargetSelection.everything());

        assertThat(targets).singleElement().satisfies(target -> {
            assertThat(target.manifest().id()).isEqualTo("brand-new-target");
            assertThat(target.manifest().check()).isEqualTo("brand-new-check");
            assertThat(target.composeFile()).isEqualTo(root.resolve("brand-new-check/brand-new-target/compose.yaml"));
        });
    }

    @Test
    void readsASeverityFloorFromTheExpectedOutcome() {
        ManifestFixtures.writeTarget(root, "check-a", "target-one", ManifestFixtures.VALID_MANIFEST
                .formatted("target-one", "check-a")
                .replace("\"expected\": { \"outcome\": \"silent\" }",
                        "\"expected\": { \"outcome\": \"silent\", \"minimumSeverity\": \"LOW\" }"));

        LoadedTarget target = ManifestFixtures.loadOnly(root, "check-a", "target-one");

        assertThat(target.manifest().arms().get(1).expected().minimumSeverity())
                .isEqualTo(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.LOW);
    }

    @Test
    void readsWhetherATargetsArmsStartFirstAndDefaultsToNot() {
        ManifestFixtures.writeValidTarget(root, "check-a", "plain");
        ManifestFixtures.writeTarget(root, "check-a", "held", ManifestFixtures.VALID_MANIFEST
                .formatted("held", "check-a").replace("\"schemaVersion\": 1,", "\"schemaVersion\": 1, \"startFirst\": true,"));

        assertThat(ManifestFixtures.loadOnly(root, "check-a", "plain").manifest().startFirst()).isFalse();
        assertThat(ManifestFixtures.loadOnly(root, "check-a", "held").manifest().startFirst()).isTrue();
    }

    @Test
    void selectsOneCheckOrOneTarget() {
        ManifestFixtures.writeValidTarget(root, "check-a", "target-one");
        ManifestFixtures.writeValidTarget(root, "check-a", "target-two");
        ManifestFixtures.writeValidTarget(root, "check-b", "target-three");
        TargetRepository repository = new TargetRepository(root);

        assertThat(repository.load(new TargetSelection(Optional.of("check-a"), Optional.empty())))
                .extracting(target -> target.manifest().id()).containsExactly("target-one", "target-two");
        assertThat(repository.load(new TargetSelection(Optional.empty(), Optional.of("target-three"))))
                .extracting(target -> target.manifest().id()).containsExactly("target-three");
    }

    @Test
    void selectsOnlySmokeTargetsWhenTheSmokeSetIsAsked() {
        ManifestFixtures.writeValidTarget(root, "check-a", "target-one");
        ManifestFixtures.writeSmokeTarget(root, "check-a", "target-two");
        ManifestFixtures.writeSmokeTarget(root, "check-b", "target-three");
        TargetRepository repository = new TargetRepository(root);

        assertThat(repository.load(TargetSelection.smokeSet()))
                .extracting(target -> target.manifest().id()).containsExactly("target-two", "target-three");
        assertThat(repository.load(new TargetSelection(Optional.of("check-a"), Optional.empty(), true)))
                .extracting(target -> target.manifest().id()).containsExactly("target-two");
        assertThat(repository.load(TargetSelection.everything()))
                .extracting(target -> target.manifest().id()).containsExactly("target-one", "target-two", "target-three");
    }

    @Test
    void portedTargetsMarkOneRealPairAndABenignTargetPerCheckAsSmoke() {
        List<LoadedTarget> smoke = new TargetRepository(PORTED_TARGETS).load(TargetSelection.smokeSet());
        List<LoadedTarget> all = new TargetRepository(PORTED_TARGETS).load(TargetSelection.everything());

        assertThat(smoke.stream().filter(target -> !target.manifest().benign()).map(target -> target.manifest().check()))
                .containsExactlyInAnyOrderElementsOf(checksWithRealPairs(all));
        assertThat(smoke).filteredOn(target -> !target.manifest().benign()).allSatisfy(target -> assertThat(target.manifest().arms())
                .extracting(TargetArm::role).contains(ArmRole.VULNERABLE, ArmRole.FIXED));
        assertThat(smoke).containsAll(benignWithinTheDefaultArmLimit(all));
        assertThat(checksWithBenignTargets(smoke)).isEqualTo(checksWithBenignTargets(all));
    }

    private static List<LoadedTarget> benignWithinTheDefaultArmLimit(List<LoadedTarget> targets) {
        return targets.stream().filter(target -> target.manifest().benign())
                .filter(target -> target.manifest().armTimeoutSeconds() <= TargetManifest.DEFAULT_ARM_TIMEOUT_SECONDS)
                .toList();
    }

    private static Set<String> checksWithRealPairs(List<LoadedTarget> targets) {
        return targets.stream().filter(target -> !target.manifest().benign())
                .map(target -> target.manifest().check()).collect(Collectors.toSet());
    }

    private static Set<String> checksWithBenignTargets(List<LoadedTarget> targets) {
        return targets.stream().filter(target -> target.manifest().benign())
                .map(target -> target.manifest().check()).collect(Collectors.toSet());
    }

    @Test
    void rejectsEveryInvalidManifestEvenWhenItIsNotSelected() {
        ManifestFixtures.writeValidTarget(root, "check-a", "target-one");
        ManifestFixtures.writeTarget(root, "check-b", "target-two", ManifestFixtures.VALID_MANIFEST.formatted("other-id", "check-b"));

        assertThatThrownBy(() -> new TargetRepository(root).load(new TargetSelection(Optional.of("check-a"), Optional.empty())))
                .isInstanceOf(InvalidTargetException.class)
                .hasMessageContaining("id must equal the target directory name target-two");
    }

    @Test
    void rejectsUnknownManifestFields() {
        ManifestFixtures.writeTarget(root, "check-a", "target-one",
                ManifestFixtures.VALID_MANIFEST.formatted("target-one", "check-a").replace("\"product\"", "\"prodcut\""));

        assertThatThrownBy(() -> new TargetRepository(root).load(TargetSelection.everything()))
                .isInstanceOf(InvalidTargetException.class)
                .hasMessageContaining("prodcut");
    }
}
