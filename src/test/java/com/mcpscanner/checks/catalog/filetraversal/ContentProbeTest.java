package com.mcpscanner.checks.catalog.filetraversal;

import com.mcpscanner.checks.catalog.filetraversal.SimulatedFileTool.Policy;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ContentProbeTest {

    private static final TraversalPayload ABSOLUTE =
            new TraversalPayload("passwd-absolute", TargetFile.PASSWD, PayloadTier.ABSOLUTE, "/etc/passwd");
    private static final TraversalPayload IN_ROOT =
            new TraversalPayload("readme", TargetFile.PASSWD, PayloadTier.IN_ROOT, "readme.txt");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void sendsMissingFileControlsOnlyForADisclosure() {
        SimulatedFileTool tool = new SimulatedFileTool(Policy.UNRESTRICTED);

        ContentTrial trial = probe(tool).run(List.of(IN_ROOT, ABSOLUTE), "mcpscan-1");

        assertThat(trial.attempts()).hasSize(2);
        assertThat(trial.confirmedReads()).singleElement().satisfies(read -> {
            assertThat(read.candidate().sentValue()).isEqualTo("/etc/passwd");
            assertThat(read.controls()).extracting(TraversalAttempt::sentValue)
                    .containsExactly("/etc/mcpscan-1", "/mcpscan-1-etc/passwd");
        });
        assertThat(tool.sent()).hasSize(4);
    }

    @Test
    void stopsAfterTheFirstConfirmedWholeFileRead() {
        SimulatedFileTool tool = new SimulatedFileTool(Policy.UNRESTRICTED);

        ContentTrial trial = probe(tool).run(List.of(ABSOLUTE, IN_ROOT), "mcpscan-1");

        assertThat(trial.attempts()).hasSize(1);
        assertThat(tool.sent()).hasSize(3);
    }

    @Test
    void keepsProbingPastAPartialDisclosure() {
        SimulatedFileTool tool = new SimulatedFileTool(Policy.PARSE_ERROR_LEAK);

        ContentTrial trial = probe(tool).run(List.of(ABSOLUTE, IN_ROOT), "mcpscan-1");

        assertThat(trial.attempts()).hasSize(2);
    }

    @Test
    void doesNotConfirmADisclosureTheControlAlsoReturns() {
        ContentTrial trial = probe(new SimulatedFileTool(Policy.ALWAYS_PASSWD)).run(List.of(ABSOLUTE), "mcpscan-1");

        assertThat(trial.confirmedReads()).isEmpty();
    }

    @Test
    void groupsResultsByFamilyAndTier() {
        TraversalPayload literal = new TraversalPayload("f", TargetFile.PASSWD, PayloadTier.TRAVERSAL, "../etc/passwd");
        TraversalPayload evasion = new TraversalPayload("f", TargetFile.PASSWD, PayloadTier.EVASION, "..%2fetc/passwd");

        ContentTrial trial = probe(new SimulatedFileTool(Policy.CONTAINED)).run(List.of(literal, evasion), "m");

        assertThat(trial.literalTwins(evasion)).extracting(TraversalAttempt::payload)
                .containsExactly(literal);
        assertThat(trial.literalTwins(literal)).isEmpty();
    }

    private static ContentProbe probe(SimulatedFileTool tool) {
        PayloadSender sender = new PayloadSender(tool.http(), new PathArgumentInsertionPoint("readme.txt"),
                Optional::empty);
        return new ContentProbe(sender, sender);
    }
}
