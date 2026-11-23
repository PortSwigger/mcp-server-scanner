package com.mcpscanner.proxy;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PinnedBasesTest {

    @Test
    void pinningPastTheCountBoundUnpinsTheLeastRecentlyUsedBase() {
        PinnedBases pins = new PinnedBases(2, Long.MAX_VALUE);
        pins.pin("first", 1);
        pins.pin("second", 1);
        pins.pin("first", 1);

        assertThat(pins.pin("third", 1)).containsExactly("second");
        assertThat(pins.isPinned("first")).isTrue();
        assertThat(pins.isPinned("second")).isFalse();
    }

    @Test
    void aBaseLookedUpRecentlySurvivesWhileAnOlderUntouchedOneIsUnpinned() {
        PinnedBases pins = new PinnedBases(2, Long.MAX_VALUE);
        pins.pin("lookedUp", 1);
        pins.pin("untouched", 1);
        pins.isPinned("lookedUp");

        assertThat(pins.pin("third", 1)).containsExactly("untouched");
        assertThat(pins.isPinned("lookedUp")).isTrue();
    }

    @Test
    void pinningPastTheByteBoundUnpinsOldestFirstButAlwaysKeepsTheNewest() {
        PinnedBases pins = new PinnedBases(10, 10);
        pins.pin("small", 4);
        pins.pin("medium", 5);

        assertThat(pins.pin("huge", 50)).containsExactly("small", "medium");
        assertThat(pins.isPinned("huge")).isTrue();
    }

    @Test
    void repinningABaseNeitherCountsItTwiceNorUnpinsAnything() {
        PinnedBases pins = new PinnedBases(1, 4);

        pins.pin("only", 4);

        assertThat(pins.pin("only", 4)).isEmpty();
        assertThat(pins.isPinned("only")).isTrue();
    }

    @Test
    void defaultBoundsAreTwoHundredFiftySixBasesAndFourMebibytes() {
        assertThat(PinnedBases.MAX_BASES).isEqualTo(256);
        assertThat(PinnedBases.MAX_BYTES).isEqualTo(4L * 1024 * 1024);
    }
}
