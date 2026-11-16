package com.mcpscanner.checks.catalog.ssrffilterbypass;

import java.util.function.Function;

enum AddressSpelling {

    MAPPED_IPV6_HEX("IPv4-mapped IPv6 address in hexadecimal", Ipv4Literal::mappedHex),
    MAPPED_IPV6_DOTTED("IPv4-mapped IPv6 address in dotted form", Ipv4Literal::mappedDotted),
    HEXADECIMAL("IPv4 address as one hexadecimal number", Ipv4Literal::hex),
    DECIMAL("IPv4 address as one decimal number", Ipv4Literal::decimal),
    OCTAL("IPv4 address in octal", Ipv4Literal::octal),
    SHORTENED("shortened IPv4 address", Ipv4Literal::shortened);

    private final String label;
    private final Function<Ipv4Literal, String> spelling;

    AddressSpelling(String label, Function<Ipv4Literal, String> spelling) {
        this.label = label;
        this.spelling = spelling;
    }

    String label() {
        return label;
    }

    String loopbackHost() {
        return spelling.apply(Ipv4Literal.LOOPBACK);
    }

    String controlHost(Ipv4Literal collaborator) {
        return spelling.apply(collaborator);
    }
}
