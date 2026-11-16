package com.mcpscanner.checks.catalog.ssrffilterbypass;

import org.junit.jupiter.api.Test;

import java.net.Inet4Address;
import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class AddressSpellingTest {

    private static final Ipv4Literal COLLABORATOR = collaborator();

    @Test
    void spellsLoopbackInEveryAlternateForm() {
        assertThat(AddressSpelling.values()).extracting(AddressSpelling::loopbackHost).containsExactly(
                "[::ffff:7f00:1]", "[::ffff:127.0.0.1]", "0x7f000001", "2130706433",
                "0177.00.00.01", "127.1");
    }

    @Test
    void spellsTheCollaboratorAddressTheSameWay() {
        assertThat(AddressSpelling.values()).extracting(spelling -> spelling.controlHost(COLLABORATOR))
                .containsExactly("[::ffff:c633:6407]", "[::ffff:198.51.100.7]", "0xc6336407", "3325256711", "0306.063.0144.07", "198.3367943");
    }

    private static Ipv4Literal collaborator() {
        try {
            return Ipv4Literal.of((Inet4Address) InetAddress.getByName("198.51.100.7"));
        } catch (java.net.UnknownHostException impossible) {
            throw new AssertionError(impossible);
        }
    }
}
