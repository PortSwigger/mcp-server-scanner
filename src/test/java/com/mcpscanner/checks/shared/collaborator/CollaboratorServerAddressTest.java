package com.mcpscanner.checks.shared.collaborator;

import burp.api.montoya.collaborator.CollaboratorServer;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class CollaboratorServerAddressTest {

    @Test
    void readsALiteralServerAddress() {
        assertThat(new CollaboratorServerAddress().ipv4(Optional.of(server("192.0.2.10"))))
                .hasValueSatisfying(address -> assertThat(address.getHostAddress()).isEqualTo("192.0.2.10"));
    }

    @Test
    void resolvesANamedServerToItsFirstIpv4Address() {
        CollaboratorServerAddress addresses = new CollaboratorServerAddress(host -> new InetAddress[]{
                InetAddress.getByName("2001:db8::1"), InetAddress.getByName("198.51.100.7")});

        assertThat(addresses.ipv4(Optional.of(server("oastify.example"))))
                .hasValueSatisfying(address -> assertThat(address.getHostAddress()).isEqualTo("198.51.100.7"));
    }

    @Test
    void hasNoAddressWhenTheServerCannotBeResolved() {
        CollaboratorServerAddress addresses = new CollaboratorServerAddress(host -> {
            throw new UnknownHostException(host);
        });

        assertThat(addresses.ipv4(Optional.of(server("oastify.example")))).isEmpty();
    }

    @Test
    void hasNoAddressWithoutAServer() {
        assertThat(new CollaboratorServerAddress().ipv4(Optional.empty())).isEmpty();
    }

    @Test
    void theWatchReportsNoAddressWhenTheClientNamesNoServer() {
        CollaboratorWatch watch = TestWatches.immediate(new FakeCollaborator());

        assertThat(watch.serverIpv4()).isEmpty();
    }

    @Test
    void theWatchReadsTheClientsServerAddress() {
        CollaboratorWatch watch = TestWatches.immediate(new FakeCollaborator() {
            @Override
            public CollaboratorServer server() {
                return CollaboratorServerAddressTest.server("192.0.2.10");
            }
        });

        assertThat(watch.serverIpv4()).isPresent();
    }

    static CollaboratorServer server(String address) {
        return new CollaboratorServer() {
            @Override
            public String address() {
                return address;
            }

            @Override
            public boolean isLiteralAddress() {
                return false;
            }
        };
    }
}
