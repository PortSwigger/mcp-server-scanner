package com.mcpscanner.auth.oauth.safety;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HostResolverTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(2);

    @Test
    void unknownHostReturnsEmptyListSoCallerCanTreatItAsHarmless() throws Exception {
        HostResolver.BoundedHostResolver resolver = new HostResolver.BoundedHostResolver(
                TIMEOUT, host -> { throw new UnknownHostException(host); });

        List<InetAddress> addresses = resolver.resolve("does-not-exist.invalid");

        assertThat(addresses).isEmpty();
    }

    @Test
    void securityExceptionDuringLookupSurfacesAsResolutionTimeoutWithCauseAttached() {
        SecurityException sandboxBlock = new SecurityException("DNS access denied by sandbox");
        HostResolver.BoundedHostResolver resolver = new HostResolver.BoundedHostResolver(
                TIMEOUT, host -> { throw sandboxBlock; });

        assertThatThrownBy(() -> resolver.resolve("sandboxed.invalid"))
                .isInstanceOf(HostResolver.ResolutionTimeoutException.class)
                .hasCauseReference(sandboxBlock)
                .hasMessageContaining("SecurityException");
    }

    @Test
    void successfulLookupReturnsAllResolvedAddresses() throws Exception {
        InetAddress address = InetAddress.getByAddress("ok.invalid", new byte[] {(byte) 203, 0, 113, 5});
        HostResolver.BoundedHostResolver resolver = new HostResolver.BoundedHostResolver(
                TIMEOUT, host -> new InetAddress[] {address});

        List<InetAddress> addresses = resolver.resolve("ok.invalid");

        assertThat(addresses).containsExactly(address);
    }

    @Test
    void resolveStillWorksAfterExecutorShutdownSoReloadIsSafe() throws Exception {
        InetAddress address = InetAddress.getByAddress("ok.invalid", new byte[] {(byte) 203, 0, 113, 5});
        HostResolver.BoundedHostResolver resolver = new HostResolver.BoundedHostResolver(
                TIMEOUT, host -> new InetAddress[] {address});
        resolver.resolve("ok.invalid");

        HostResolver.shutdownExecutor();

        assertThat(resolver.resolve("ok.invalid")).containsExactly(address);
    }
}
