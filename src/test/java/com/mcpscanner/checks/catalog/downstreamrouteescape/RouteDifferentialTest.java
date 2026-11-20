package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class RouteDifferentialTest {

    private static final RouteProbe PROBE = new RouteProbe(List.of("../", ".././"),
            List.of(".../", "..././", ".../mcp/../"), List.of());
    private static final RouteProbe BARE = new RouteProbe(List.of("..", ".."), List.of("...", "...."), List.of("."));

    private static final ReplySignature SIGNATURES = new ReplySignature(new PayloadMask());

    private final RouteDifferential differential = new RouteDifferential(SIGNATURES,
            new AcceptedReply(SIGNATURES, new RejectionWording()));

    @Test
    void stableTraversalResultThatDiffersFromStableControlsIsADifference() {
        ScriptedSender sender = new ScriptedSender(RouteDifferentialTest::router);

        Optional<RouteDifference> difference = run(PROBE, sender);

        assertThat(difference).isPresent();
        assertThat(difference.get().probe()).isEqualTo(PROBE);
        assertThat(sender.sent).containsExactly("../", ".././", ".../", "..././", ".../mcp/../", "../", ".../");
        assertThat(difference.get().evidence()).extracting(SentValue::value).containsExactly("../", ".../");
    }

    @Test
    void evidenceHoldsTheFirstTraversalAndControlExchangesNotTheirRepeats() {
        HttpRequestResponse traversal = Replies.toolText("{\"service\":\"index\"}");
        HttpRequestResponse control = Replies.toolText("{\"error\":\"not found\"}");
        ScriptedSender sender = new ScriptedSender(RouteDifferentialTest::router)
                .then("../", traversal).then(".../", control);

        RouteDifference difference = run(PROBE, sender).orElseThrow();

        assertThat(difference.evidence()).extracting(SentValue::exchange).containsExactly(traversal, control);
    }

    @Test
    void traversalToolErrorStopsAfterTheFirstRequest() {
        ScriptedSender sender = new ScriptedSender(value -> Replies.toolError("invalid id"));

        assertThat(run(PROBE, sender)).isEmpty();
        assertThat(sender.sent).containsExactly("../");
    }

    @Test
    void traversalSpellingsThatDisagreeAreNotADifference() {
        ScriptedSender sender = new ScriptedSender(RouteDifferentialTest::router)
                .then(".././", Replies.toolText("{\"other\":true}"));

        assertThat(run(PROBE, sender)).isEmpty();
        assertThat(sender.sent).containsExactly("../", ".././");
    }

    @Test
    void controlsMatchingTheTraversalAreNotADifference() {
        ScriptedSender sender = new ScriptedSender(value -> Replies.toolText("{\"error\":\"not found\"}"));

        assertThat(run(PROBE, sender)).isEmpty();
    }

    @Test
    void resultsThatDifferOnlyInATimingValueAreNotADifference() {
        ScriptedSender sender = new ScriptedSender(value -> Replies.toolText(value.startsWith("...")
                ? "{\"status\":\"ok\",\"responseTimeMs\":7}"
                : "{\"status\":\"ok\",\"responseTimeMs\":5}"));

        assertThat(run(PROBE, sender)).isEmpty();
    }

    @Test
    void aContrastThatDiffersFromTheTraversalOnlyInATimingValueIsNotADifference() {
        ScriptedSender sender = new ScriptedSender(value -> switch (value) {
            case "..", "." -> Replies.toolText("{\"items\":[],\"tookMs\":" + value.length() + "}");
            default -> Replies.toolText("{\"error\":\"not found\"}");
        });

        assertThat(run(BARE, sender)).isEmpty();
    }

    @Test
    void aDownstreamStatusThatDiffersOnlyInItsNumberIsStillADifference() {
        ScriptedSender sender = new ScriptedSender(value -> Replies.toolText(value.startsWith("...")
                ? "{\"ok\":false,\"message\":\"Request failed with status code 404\"}"
                : "{\"ok\":false,\"message\":\"Request failed with status code 403\"}"));

        assertThat(run(PROBE, sender)).isPresent();
    }

    @Test
    void controlsThatDisagreeWithEachOtherAreNotADifference() {
        ScriptedSender sender = new ScriptedSender(RouteDifferentialTest::router)
                .then("..././", Replies.toolText("{\"error\":\"rate limited\"}"));

        assertThat(run(PROBE, sender)).isEmpty();
    }

    @Test
    void traversalThatChangesOnRepeatIsNotADifference() {
        ScriptedSender sender = new ScriptedSender(RouteDifferentialTest::router)
                .then("../", Replies.toolText("{\"service\":\"index\"}"))
                .then("../", Replies.toolText("{\"service\":\"index\",\"t\":2}"));

        assertThat(run(PROBE, sender)).isEmpty();
    }

    @Test
    void controlThatChangesOnRepeatIsNotADifference() {
        ScriptedSender sender = new ScriptedSender(RouteDifferentialTest::router)
                .then(".../", Replies.toolText("{\"error\":\"not found\"}"))
                .then(".../", Replies.toolText("{\"error\":\"timeout\"}"));

        assertThat(run(PROBE, sender)).isEmpty();
    }

    @Test
    void controlToolErrorsStillCountAsAStableControlResult() {
        ScriptedSender sender = new ScriptedSender(value -> value.startsWith("...")
                ? Replies.toolError("no such license") : Replies.toolText("{\"service\":\"index\"}"));

        assertThat(run(PROBE, sender)).isPresent();
    }

    @Test
    void traversalResultStatingARejectionIsNotADifference() {
        ScriptedSender sender = new ScriptedSender(value -> value.startsWith("...")
                ? Replies.toolText("{\"status\":404,\"detail\":\"missing\"}")
                : Replies.toolText("{\"status\":400,\"detail\":\"Invalid identifier: path separators are not allowed\"}"));

        assertThat(run(PROBE, sender)).isEmpty();
    }

    @Test
    void validatorRejectingDotSegmentsInAnyWordingIsNotADifference() {
        ScriptedSender sender = new ScriptedSender(value -> List.of(value.split("/")).contains("..")
                ? Replies.toolText("{\"message\":\"segments must be plain names\"}")
                : Replies.toolText("{\"error\":\"not found\"}"));

        assertThat(run(PROBE, sender)).isEmpty();
    }

    @Test
    void bareParentThatReachesADifferentRouteFromTheCurrentSegmentIsADifference() {
        ScriptedSender sender = new ScriptedSender(value -> switch (value) {
            case ".." -> Replies.toolText("{\"service\":\"index\"}");
            case "." -> Replies.toolText("{\"items\":[]}");
            default -> Replies.toolText("{\"error\":\"not found\"}");
        });

        Optional<RouteDifference> difference = run(BARE, sender);

        assertThat(difference).isPresent();
        assertThat(sender.sent).containsExactly("..", "..", "...", "....", ".", "..", "...");
        assertThat(difference.get().evidence()).extracting(SentValue::value).containsExactly("..", "...", ".");
    }

    @Test
    void bareParentAnsweredLikeTheCurrentSegmentIsNotADifference() {
        ScriptedSender sender = new ScriptedSender(value -> value.length() <= 2
                ? Replies.toolText("{\"message\":\"segment may not be a dot segment\"}")
                : Replies.toolText("{\"error\":\"not found\"}"));

        assertThat(run(BARE, sender)).isEmpty();
    }

    @Test
    void echoingToolIsNotADifference() {
        ScriptedSender sender = new ScriptedSender(value -> Replies.toolText("you asked for " + value));

        assertThat(run(PROBE, sender)).isEmpty();
    }

    @Test
    void pathNormalisingToolIsNotADifference() {
        ScriptedSender sender = new ScriptedSender(value -> Replies.toolText(
                value.startsWith("...") ? "{\"normalized\":\"...\"}" : "{\"normalized\":\"..\"}"));

        assertThat(run(PROBE, sender)).isEmpty();
    }

    @Test
    void onlyTheFirstTraversalIsAProbeAndEverySendThatConfirmsItIsAConfirmation() {
        ScriptedSender probes = new ScriptedSender(RouteDifferentialTest::router);
        ScriptedSender confirmations = new ScriptedSender(RouteDifferentialTest::router);

        assertThat(differential.run(PROBE, new RouteSenders(probes, confirmations))).isPresent();

        assertThat(probes.sent).containsExactly("../");
        assertThat(confirmations.sent).containsExactly(".././", ".../", "..././", ".../mcp/../", "../", ".../");
    }

    private Optional<RouteDifference> run(RouteProbe probe, ScriptedSender sender) {
        return differential.run(probe, new RouteSenders(sender, sender));
    }

    private static HttpRequestResponse router(String value) {
        return value.startsWith("...") ? Replies.toolText("{\"error\":\"not found\"}")
                : Replies.toolText("{\"service\":\"index\"}");
    }
}
