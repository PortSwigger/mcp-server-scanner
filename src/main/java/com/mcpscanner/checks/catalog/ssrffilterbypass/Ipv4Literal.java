package com.mcpscanner.checks.catalog.ssrffilterbypass;

import java.net.Inet4Address;
import java.nio.ByteBuffer;
import java.util.function.IntFunction;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

record Ipv4Literal(int value) {

    static final Ipv4Literal LOOPBACK = new Ipv4Literal(0x7f000001);

    static Ipv4Literal of(Inet4Address address) {
        return new Ipv4Literal(ByteBuffer.wrap(address.getAddress()).getInt());
    }

    String dotted() {
        return octets(Integer::toString);
    }

    String mappedHex() {
        return "[::ffff:" + Integer.toHexString(value >>> 16) + ":" + Integer.toHexString(value & 0xffff) + "]";
    }

    String mappedDotted() {
        return "[::ffff:" + dotted() + "]";
    }

    String hex() {
        return String.format("0x%08x", value);
    }

    String decimal() {
        return Long.toString(Integer.toUnsignedLong(value));
    }

    String octal() {
        return octets(octet -> "0" + Integer.toOctalString(octet));
    }

    String shortened() {
        return octet(0) + "." + (value & 0xffffff);
    }

    private String octets(IntFunction<String> spelling) {
        return IntStream.range(0, 4).map(this::octet).mapToObj(spelling).collect(Collectors.joining("."));
    }

    private int octet(int index) {
        return (value >>> (24 - 8 * index)) & 0xff;
    }
}
