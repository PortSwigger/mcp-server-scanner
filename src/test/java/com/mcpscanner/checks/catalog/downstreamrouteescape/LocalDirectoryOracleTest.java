package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LocalDirectoryOracleTest {

    private static final String COMMITTED = "git add . && git commit";
    private static final String NO_DIRECTORY = "Error: spawn git ENOENT";

    private final ReplySignature signatures = new ReplySignature(new PayloadMask());
    private final LocalDirectoryOracle oracle = new LocalDirectoryOracle(signatures,
            new AcceptedReply(signatures, new RejectionWording()));

    @Test
    void existingAbsoluteDirectoriesAcceptedAndAMissingOneAnsweredLikeTheControlsIsALocalDirectory() {
        ScriptedSender sender = new ScriptedSender(LocalDirectoryOracleTest::changeDirectory);

        assertThat(oracle.explains(controlOf(".../"), sender)).isTrue();
        assertThat(sender.sent).containsExactly("/etc/", "/usr/", LocalDirectoryOracle.MISSING_DIRECTORY);
    }

    @Test
    void aRouteThatDoesNotKnowTheFirstAbsoluteDirectoryStopsAfterOneRequest() {
        ScriptedSender sender = new ScriptedSender(value -> Replies.toolText("{\"error\":\"not found\"}"));

        assertThat(oracle.explains(difference(Replies.toolText("{\"error\":\"not found\"}"), ".../"), sender))
                .isFalse();
        assertThat(sender.sent).containsExactly("/etc/");
    }

    @Test
    void anAbsoluteDirectoryAnsweredLikeTheControlsIsNotALocalDirectory() {
        ScriptedSender sender = new ScriptedSender(LocalDirectoryOracleTest::changeDirectory)
                .then("/usr/", Replies.toolText(NO_DIRECTORY));

        assertThat(oracle.explains(controlOf(".../"), sender)).isFalse();
    }

    @Test
    void aRejectedAbsoluteDirectoryIsNotALocalDirectory() {
        ScriptedSender sender = new ScriptedSender(LocalDirectoryOracleTest::changeDirectory)
                .then("/etc/", Replies.toolText("absolute paths are not allowed"));

        assertThat(oracle.explains(controlOf(".../"), sender)).isFalse();
    }

    @Test
    void aMissingAbsoluteDirectoryAnsweredUnlikeTheControlsIsNotALocalDirectory() {
        ScriptedSender sender = new ScriptedSender(LocalDirectoryOracleTest::changeDirectory)
                .then(LocalDirectoryOracle.MISSING_DIRECTORY, Replies.toolText(COMMITTED));

        assertThat(oracle.explains(controlOf(".../"), sender)).isFalse();
    }

    private RouteDifference controlOf(String control) {
        return difference(changeDirectory(control), control);
    }

    private RouteDifference difference(HttpRequestResponse controlReply, String control) {
        RouteProbe probe = new RouteProbe(List.of("../"), List.of(control), List.of());
        return new RouteDifference(probe, List.of(), signatures.of(controlReply, control));
    }

    private static HttpRequestResponse changeDirectory(String value) {
        boolean exists = value.equals("../") || value.equals("/etc/") || value.equals("/usr/");
        return Replies.toolText(exists ? COMMITTED : NO_DIRECTORY);
    }
}
