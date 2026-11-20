package com.mcpscanner.cvetargets.manifest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignedInSessionValidatorTest {

    private static final String SCRIPT = "sign_in.py";

    @TempDir
    Path root;

    @Test
    void loadsASignedInSessionWhoseProvisionScriptIsInTheTargetDirectory() throws IOException {
        LoadedTarget target = load(signedInSession("{ \"provision\": \"" + SCRIPT + "\" }"), true);

        assertThat(target.manifest().signedInSession().declared()).isTrue();
        assertThat(target.manifest().signedInSession().provision()).isEqualTo(SCRIPT);
    }

    @Test
    void leavesATargetWithoutASignedInSessionUndeclared() throws IOException {
        LoadedTarget target = load(ManifestFixtures.VALID_MANIFEST.formatted("target-one", "check-a"), false);

        assertThat(target.manifest().signedInSession().declared()).isFalse();
    }

    @Test
    void rejectsAMissingOrEscapingProvisionScript() throws IOException {
        assertInvalid(signedInSession("{ \"provision\": \"" + SCRIPT + "\" }"),
                "signedInSession: provision script sign_in.py does not exist in the target directory");
        assertInvalid(signedInSession("{ \"provision\": \"../" + SCRIPT + "\" }"),
                "signedInSession: provision script ../sign_in.py does not exist in the target directory");
    }

    @Test
    void rejectsASignedInSessionWithoutAProvisionScript() {
        ManifestFixtures.writeTarget(root, "check-a", "target-one", signedInSession("{ }"));

        assertThatThrownBy(() -> new TargetRepository(root).load(TargetSelection.everything()))
                .isInstanceOf(InvalidTargetException.class)
                .hasMessageContaining("provision");
    }

    @Test
    void letsTheSignedInSessionProvisionThePrimaryCredential() throws IOException {
        String manifest = signedInSession("{ \"provision\": \"" + SCRIPT + "\" }").replace(
                "\"auth\": { \"scheme\": \"none\" },",
                "\"auth\": { \"scheme\": \"bearer\", \"obtain\": \"signed-in session provision\","
                        + " \"token\": { \"source\": \"provisioned\" } },");

        assertThat(load(manifest, true).manifest().auth().token()).isInstanceOf(ProvisionedToken.class);
    }

    private void assertInvalid(String manifest, String violation) {
        ManifestFixtures.writeTarget(root, "check-a", "target-one", manifest);
        assertThatThrownBy(() -> new TargetRepository(root).load(TargetSelection.everything()))
                .isInstanceOf(InvalidTargetException.class)
                .hasMessageContaining(violation);
    }

    private LoadedTarget load(String manifest, boolean withScript) throws IOException {
        Path directory = ManifestFixtures.writeTarget(root, "check-a", "target-one", manifest);
        if (withScript) {
            Files.writeString(directory.resolve(SCRIPT), "#!/bin/sh\n");
        }
        return ManifestFixtures.loadOnly(root, "check-a", "target-one");
    }

    private static String signedInSession(String body) {
        return ManifestFixtures.VALID_MANIFEST.formatted("target-one", "check-a")
                .replace("\"arms\": [", "\"signedInSession\": " + body + ",\n  \"arms\": [");
    }
}
