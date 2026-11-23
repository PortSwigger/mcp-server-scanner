package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LaunchedBasesTest {

    private static final String BODY = "{\"id\":1,\"method\":\"tools/call\"}";

    @Test
    void onlyTheFirstSendOfALaunchedBodyIsItsBase() {
        LaunchedBases bases = new LaunchedBases();
        bases.remember(BODY);

        assertThat(bases.claimFirstSend(BODY)).isTrue();
        assertThat(bases.claimFirstSend(BODY)).isFalse();
    }

    @Test
    void aBodyThatWasNeverLaunchedIsNeverABase() {
        LaunchedBases bases = new LaunchedBases();
        bases.remember(BODY);

        assertThat(bases.claimFirstSend(BODY.replace("1", "2"))).isFalse();
        assertThat(bases.claimFirstSend(null)).isFalse();
    }

    @Test
    void launchingTheSameBodyAgainMakesItsNextSendABaseAgain() {
        LaunchedBases bases = new LaunchedBases();
        bases.remember(BODY);
        bases.claimFirstSend(BODY);

        bases.remember(BODY);

        assertThat(bases.claimFirstSend(BODY)).isTrue();
    }

    @Test
    void forgetsTheOldestLaunchOnceItsBoundIsReached() {
        LaunchedBases bases = new LaunchedBases(2);
        bases.remember("first");
        bases.remember("second");
        bases.remember("third");

        assertThat(bases.claimFirstSend("first")).isFalse();
        assertThat(bases.claimFirstSend("second")).isTrue();
        assertThat(bases.claimFirstSend("third")).isTrue();
    }

    @Test
    void remembersUpToFourThousandNinetySixLaunchesByDefault() {
        assertThat(LaunchedBases.MAX_BODIES).isEqualTo(4_096);
    }
}
