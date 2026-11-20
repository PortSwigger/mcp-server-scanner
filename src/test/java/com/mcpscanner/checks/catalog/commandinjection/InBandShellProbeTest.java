package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.catalog.commandinjection.SimulatedToolServer.ToolReply;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

class InBandShellProbeTest {

    private static final ArithmeticCanary CANARY = new ArithmeticCanary(200_000_000L, 300_000_000L);
    private static final String BASE = SimulatedToolServer.BASE_VALUE;
    private static final ArithmeticCanary FRESH = new ArithmeticCanary(400_000_000L, 500_000_000L);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void stopsAtTheFirstBreakoutThatComputesAndRepeatsItWithAFreshCanary() {
        SimulatedToolServer server = server(ToolBehaviours.shellCommandLine());

        ProbeOutcome result = probe(server);

        assertThat(result.finding()).hasValueSatisfying(finding -> {
            assertThat(finding.kind()).isEqualTo(FindingKind.SHELL_COMPUTED_RESULT);
        });
        assertThat(server.probeCount()).isEqualTo(5);
        assertThat(server.receivedValues()).anyMatch(value -> value.contains(FRESH.command()));
    }

    @Test
    void aRepeatThatNoLongerComputesIsInconclusive() {
        Function<String, ToolReply> shell = ToolBehaviours.shellCommandLine();
        Function<String, ToolReply> computesOnce = value -> value.contains(FRESH.command())
                ? ToolReply.ok("PING " + value) : shell.apply(value);

        assertThat(probe(server(computesOnce)).finding()).isEmpty();
    }

    @Test
    void aDirectCommandThatComputesOnlyOnTheRepeatIsAnIntendedCommand() {
        Function<String, ToolReply> runner = ToolBehaviours.commandRunner();
        Function<String, ToolReply> unreliable = value -> value.equals(CANARY.command())
                ? ToolReply.ok("I could not run that") : runner.apply(value);

        assertThat(probe(server(unreliable)).finding()).map(Finding::kind).hasValue(FindingKind.INTENDED_COMMAND);
    }

    @Test
    void triesEveryBreakoutWhenNoneComputes() {
        SimulatedToolServer server = server(ToolBehaviours.argumentVector());

        ProbeOutcome result = probe(server);

        assertThat(result.conclusive()).isFalse();
        assertThat(server.probeCount()).isEqualTo(ShellBreakout.values().length);
    }

    @Test
    void aComputingDirectCommandIsReportedAsAnIntendedCommand() {
        ProbeOutcome result = probe(server(ToolBehaviours.commandRunner()));

        assertThat(result.finding()).map(Finding::kind).hasValue(FindingKind.INTENDED_COMMAND);
    }

    @Test
    void aMatchedControlThatAlsoComputesIsNotEvidence() {
        Function<String, ToolReply> computesAnything = value -> ToolReply.ok(value.contains("$(printf")
                || value.endsWith("mcp-control") ? CANARY.result() : "ok");

        assertThat(probe(server(computesAnything)).finding()).isEmpty();
    }

    @Test
    void aQuotedControlThatStillComputesIsNotEvidence() {
        assertThat(probe(server(ToolBehaviours.rejectingTheMatchedControl(
                ToolBehaviours.arithmeticTemplateThenShell()))).finding()).isEmpty();
    }

    @Test
    void readsTheExpansionFromAToolErrorThroughTheQuotedLiteralControl() {
        ProbeOutcome result = probe(server(ToolBehaviours.shellEchoingTheExpandedArgumentInItsError(
                SimulatedToolServer.BASE_VALUE)));

        assertThat(result.finding()).map(Finding::kind).hasValue(FindingKind.SHELL_COMPUTED_RESULT_QUOTED_CONTROL);
    }

    @Test
    void anErrorThatOnlyReflectsTheRequestIsNotEvidence() {
        assertThat(probe(server(value -> SimulatedToolServer.ToolReply.toolError("bad value: " + value))).finding())
                .isEmpty();
    }

    @Test
    void aShellRunAfterATemplatePassIsStillShellInjection() {
        assertThat(probe(server(ToolBehaviours.arithmeticTemplateThenShell())).finding()).map(Finding::kind)
                .hasValue(FindingKind.SHELL_COMPUTED_RESULT);
    }

    @Test
    void aQuotedControlThatFailsIsInconclusive() {
        Function<String, ToolReply> allowlisted = ToolBehaviours.shellCommandLineAllowingFirstToken(
                SimulatedToolServer.BASE_VALUE);
        Function<String, ToolReply> rejectingQuotes = value -> value.contains("'$((")
                ? ToolReply.toolError("Error: quotes") : allowlisted.apply(value);

        assertThat(probe(server(rejectingQuotes)).finding()).isEmpty();
    }

    @Test
    void aShellComputedResultAttachesTheBaselineTheInjectedValueAndTheFirstBareCommandThatDidNotCompute() {
        SimulatedToolServer server = server(ToolBehaviours.shellCommandLine());

        Finding finding = probe(server).finding().orElseThrow();

        assertThat(finding.kind()).isEqualTo(FindingKind.SHELL_COMPUTED_RESULT);
        assertThat(server.valuesSentIn(finding.evidence()))
                .containsExactly(BASE, BASE + "$(" + CANARY.command() + ")", CANARY.command());
    }

    @Test
    void aQuotedControlFindingAttachesTheBareCommandAndTheQuotedControlButNotTheRejectedMatchedControl() {
        SimulatedToolServer server = server(ToolBehaviours.shellCommandLineAllowingFirstToken(BASE));

        Finding finding = probe(server).finding().orElseThrow();

        assertThat(finding.kind()).isEqualTo(FindingKind.SHELL_COMPUTED_RESULT_QUOTED_CONTROL);
        assertThat(server.valuesSentIn(finding.evidence())).containsExactly(BASE,
                BASE + "$(" + CANARY.command() + ")", CANARY.command(), BASE + "$(" + CANARY.quotedCommand() + ")");
    }

    @Test
    void anIntendedCommandFoundDirectlyAttachesTheBareCommandThatComputed() {
        SimulatedToolServer server = server(ToolBehaviours.commandRunner());

        Finding finding = probe(server).finding().orElseThrow();

        assertThat(server.valuesSentIn(finding.evidence()))
                .containsExactly(BASE, BASE + "$(" + CANARY.command() + ")", CANARY.command());
    }

    @Test
    void anIntendedCommandFoundOnTheRepeatAttachesOnlyTheBareCommandThatComputed() {
        Function<String, ToolReply> runner = ToolBehaviours.commandRunner();
        SimulatedToolServer server = server(value -> value.equals(CANARY.command())
                ? ToolReply.ok("I could not run that") : runner.apply(value));

        Finding finding = probe(server).finding().orElseThrow();

        assertThat(finding.kind()).isEqualTo(FindingKind.INTENDED_COMMAND);
        assertThat(server.valuesSentIn(finding.evidence()))
                .containsExactly(BASE, BASE + "$(" + CANARY.command() + ")", FRESH.command());
    }

    private static SimulatedToolServer server(Function<String, ToolReply> behaviour) {
        return new SimulatedToolServer("tool", "arg", behaviour);
    }

    private static ProbeOutcome probe(SimulatedToolServer server) {
        HttpRequestResponse base = server.baseline();
        ProbeField field = server.probeField(base);
        return new InBandShellProbe(() -> FRESH).probe(field, field.baseline(), CANARY);
    }
}
