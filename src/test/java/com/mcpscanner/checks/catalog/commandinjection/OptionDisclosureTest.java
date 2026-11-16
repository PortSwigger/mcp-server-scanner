package com.mcpscanner.checks.catalog.commandinjection;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OptionDisclosureTest {

    @Test
    void findsLongAndShortOptionNamesButNotHyphenatedWordsOrTheSentOption() {
        String usage = "re-run with -o, --output=json or -A; see --help. Use well-known  - values";

        assertThat(OptionDisclosure.OPTION_NAMES.in(usage, ProgramOption.HELP))
                .containsExactly("--output", "-A", "-o");
    }

    @Test
    void findsAThreePartVersionButNotAnAddressOrATwoPartNumber() {
        String text = "Client Version: v1.35.6 at 10.0.0.12, load 0.75. Built 2.1.0.";

        assertThat(OptionDisclosure.VERSION_NUMBER.in(text, ProgramOption.VERSION))
                .containsExactly("1.35.6", "2.1.0");
    }

    @Test
    void stripsTheLeadingDashesForTheControlWord() {
        assertThat(ProgramOption.HELP.undashed()).isEqualTo("help");
        assertThat(ProgramOption.VERSION.undashed()).isEqualTo("version");
    }
}
