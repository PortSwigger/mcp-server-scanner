package com.mcpscanner.checks.shared.collaborator;

import burp.api.montoya.collaborator.CollaboratorServer;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public final class CollaboratorServerAddress {

    @FunctionalInterface
    interface HostResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private final HostResolver resolver;
    private final Map<String, Inet4Address> resolved = new ConcurrentHashMap<>();

    public CollaboratorServerAddress() {
        this(InetAddress::getAllByName);
    }

    CollaboratorServerAddress(HostResolver resolver) {
        this.resolver = resolver;
    }

    public Optional<Inet4Address> ipv4(Optional<CollaboratorServer> server) {
        return server.map(CollaboratorServer::address).filter(address -> !address.isBlank())
                .map(address -> resolved.computeIfAbsent(address, host -> firstIpv4(host).orElse(null)));
    }

    private Optional<Inet4Address> firstIpv4(String host) {
        try {
            return Arrays.stream(resolver.resolve(host)).filter(Inet4Address.class::isInstance)
                    .map(Inet4Address.class::cast).findFirst();
        } catch (UnknownHostException | RuntimeException unresolved) {
            return Optional.empty();
        }
    }
}
