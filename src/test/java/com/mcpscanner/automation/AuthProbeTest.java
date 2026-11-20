package com.mcpscanner.automation;

import com.mcpscanner.auth.oauth.discovery.AuthRequirement;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthProbeTest {

    private static final String URL = "http://127.0.0.1:8123/mcp";

    private final AtomicLong clock = new AtomicLong();
    private final List<Boolean> networkingSettings = new ArrayList<>();
    private final List<String> events = new ArrayList<>();

    @Test
    void appliesTheNetworkingSettingBeforeProbingAndReportsTheTimedClassification() {
        AuthProbe probe = new AuthProbe(this::setNetworking, uri -> {
            events.add("probe " + uri);
            clock.addAndGet(TimeUnit.MILLISECONDS.toNanos(42));
            return new AuthRequirement.CredentialsRequired("needs credentials", true);
        }, clock::get);

        AuthProbeReport report = probe.run(new AuthProbeCommand(URL, true));

        assertThat(events).containsExactly("networking true", "probe " + URL);
        assertThat(report.requirement()).isEqualTo("CredentialsRequired");
        assertThat(report.detail()).contains("needs credentials", "bearerExpected=true");
        assertThat(report.elapsedMillis()).isEqualTo(42);
    }

    @Test
    void probesDirectlyWhenBurpNetworkingIsOff() {
        AuthProbe probe = new AuthProbe(this::setNetworking, uri -> new AuthRequirement.NotRequired(), clock::get);

        AuthProbeReport report = probe.run(new AuthProbeCommand(URL, false));

        assertThat(networkingSettings).containsExactly(false);
        assertThat(report.requirement()).isEqualTo("NotRequired");
    }

    @Test
    void refusesAUrlThatIsNotHttp() {
        assertThatThrownBy(() -> new AuthProbeCommand("file:///etc/passwd", true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuthProbeCommand(null, true)).isInstanceOf(IllegalArgumentException.class);
    }

    private void setNetworking(boolean useBurp) {
        networkingSettings.add(useBurp);
        events.add("networking " + useBurp);
    }
}
