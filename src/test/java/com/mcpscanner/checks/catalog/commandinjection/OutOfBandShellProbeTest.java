package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.shared.collaborator.TaggingCopies;
import com.mcpscanner.checks.shared.collaborator.TestWatches;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

class OutOfBandShellProbeTest {

    private final FakeCollaborator collaborator = new FakeCollaborator();
    private final List<Finding> confirmed = new ArrayList<>();

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void sendsOneFreshPayloadPerBreakoutAndReportsTheContactedOnesOnceTheyInteract() {
        SimulatedToolServer server = new SimulatedToolServer("archive", "label",
                ToolBehaviours.blindShell(collaborator::resolve));
        CollaboratorWatch watch = TestWatches.immediate(collaborator::available);

        probe(server, watch);
        boolean reportedBeforeAnyPoll = !confirmed.isEmpty();
        watch.awaitSettled();

        assertThat(reportedBeforeAnyPoll).isFalse();
        assertThat(collaborator.generatedHosts()).doesNotHaveDuplicates().hasSize(ShellBreakout.values().length);
        assertThat(confirmed).singleElement().satisfies(found -> {
            assertThat(found.kind()).isEqualTo(FindingKind.SHELL_OUT_OF_BAND);
            assertThat(found.technique()).isEqualTo("Collaborator DNS interaction from the $(...) command "
                    + "substitution breakout, whose request is attached; the backtick, semicolon, newline, "
                    + "double-quote and single-quote breakouts also caused interactions");
            assertThat(server.valuesSentIn(found.evidence())).singleElement().asString()
                    .startsWith(SimulatedToolServer.BASE_VALUE + "$(nslookup payload0");
        });
        assertThat(watch.watchedCount()).isZero();
    }

    @Test
    void namesNoOtherBreakoutWhenOnlyOneCausedAnInteraction() {
        java.util.function.Function<String, SimulatedToolServer.ToolReply> shell =
                ToolBehaviours.blindShell(collaborator::resolve);
        SimulatedToolServer server = new SimulatedToolServer("archive", "label",
                value -> value.startsWith(SimulatedToolServer.BASE_VALUE + "; ") ? shell.apply(value)
                        : SimulatedToolServer.ToolReply.ok("done"));
        CollaboratorWatch watch = TestWatches.immediate(collaborator::available);

        probe(server, watch);
        watch.awaitSettled();

        assertThat(confirmed).singleElement().satisfies(found -> {
            assertThat(found.technique()).isEqualTo(
                    "Collaborator DNS interaction from the semicolon breakout, whose request is attached");
            assertThat(server.valuesSentIn(found.evidence())).singleElement().asString()
                    .startsWith(SimulatedToolServer.BASE_VALUE + "; nslookup payload2");
        });
    }

    @Test
    void keepsEveryBreakoutExchangeAsTheWatchsTemporaryFileCopy() {
        SimulatedToolServer server = new SimulatedToolServer("archive", "label",
                ToolBehaviours.blindShell(collaborator::resolve));
        TaggingCopies copies = new TaggingCopies();
        CollaboratorWatch watch = TestWatches.keepingIn(collaborator::available, copies);

        probe(server, watch);
        watch.awaitSettled();

        assertThat(copies.keptCount()).isEqualTo(ShellBreakout.values().length);
        assertThat(confirmed).singleElement()
                .satisfies(found -> assertThat(found.evidence()).allMatch(TaggingCopies::wasKept));
    }

    @Test
    void keepsWatchingWithoutAnInteraction() {
        SimulatedToolServer server = new SimulatedToolServer("archive", "label", ToolBehaviours.reflecting());
        CollaboratorWatch watch = TestWatches.immediate(collaborator::available);

        probe(server, watch);
        watch.awaitSettled();

        assertThat(confirmed).isEmpty();
        assertThat(watch.watchedCount()).isEqualTo(1);
    }

    @Test
    void sendsNothingWhenTheCollaboratorSupplierFails() {
        SimulatedToolServer server = new SimulatedToolServer("archive", "label", ToolBehaviours.reflecting());
        Supplier<Optional<CollaboratorClient>> failing = () -> {
            throw new IllegalStateException("no Burp Collaborator");
        };

        probe(server, TestWatches.immediate(failing));

        assertThat(server.probeCount()).isZero();
    }

    private void probe(SimulatedToolServer server, CollaboratorWatch watch) {
        HttpRequestResponse base = server.baseline();
        new OutOfBandShellProbe(watch,
                new CheckLog(McpEventLog.noop(), CommandInjectionDescriptor.DESCRIPTOR.id())).probe(server.probeField(base),
                confirmed::add);
    }
}
