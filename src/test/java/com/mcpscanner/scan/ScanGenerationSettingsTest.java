package com.mcpscanner.scan;

import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.scan.request.AdvertisedAuthorizationServer;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.RequestGenerator;
import com.mcpscanner.scan.request.ScanMessage;
import com.mcpscanner.scan.request.ServerCapabilities;
import com.mcpscanner.scan.request.ServerSurface;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ScanGenerationSettingsTest {

    private final ExtensionConfigStore store = InMemoryPersistedObject.configStore();
    private final ScanGenerationSettings settings = new ScanGenerationSettings(store);

    @Test
    void everyFamilyAndHeaderFieldsAreOnByDefault() {
        assertThat(RequestFamily.values()).allMatch(settings::isEnabled);
        assertThat(settings.headerFieldsEnabled()).isTrue();
    }

    @Test
    void metaEnvelopeIsFuzzedOncePerServerByDefault() {
        assertThat(settings.metaEnvelopeFuzzedOnEveryRequest()).isFalse();
    }

    @Test
    void metaEnvelopeOnEveryRequestSwitchPersists() {
        settings.setMetaEnvelopeFuzzedOnEveryRequest(true);

        assertThat(new ScanGenerationSettings(store).metaEnvelopeFuzzedOnEveryRequest()).isTrue();
    }

    @Test
    void clientRegistrationIsSentByDefaultExactlyWhenTheServerAdvertisesARegistrationEndpoint() {
        ScanInventory empty = new ScanInventory(List.of(), List.of(), List.of(), List.of());
        ServerSurface advertising = new ServerSurface(empty, ServerCapabilities.none(), null,
                () -> Optional.of(URI.create("https://auth.example.test/register")));
        ServerSurface silent = new ServerSurface(empty, ServerCapabilities.none(), null,
                AdvertisedAuthorizationServer.none());

        assertThat(families(RequestGenerator.standard().scanAll(advertising, settings)))
                .contains(RequestFamily.CLIENT_REGISTRATION);
        assertThat(families(RequestGenerator.standard().scanAll(silent, settings)))
                .doesNotContain(RequestFamily.CLIENT_REGISTRATION);
    }

    @Test
    void switchingClientRegistrationOffSuppressesItEvenWhenAdvertised() {
        settings.setEnabled(RequestFamily.CLIENT_REGISTRATION, false);
        ServerSurface advertising = new ServerSurface(new ScanInventory(List.of(), List.of(), List.of(), List.of()),
                ServerCapabilities.none(), null, () -> Optional.of(URI.create("https://auth.example.test/register")));

        assertThat(families(RequestGenerator.standard().scanAll(advertising, settings)))
                .doesNotContain(RequestFamily.CLIENT_REGISTRATION);
    }

    private static List<RequestFamily> families(GeneratedScan scan) {
        return scan.messages().stream().map(ScanMessage::family).toList();
    }

    @ParameterizedTest
    @EnumSource(RequestFamily.class)
    void switchingOneFamilyOffPersistsAndLeavesOthersOn(RequestFamily family) {
        settings.setEnabled(family, false);

        ScanGenerationSettings reloaded = new ScanGenerationSettings(store);
        assertThat(reloaded.isEnabled(family)).isFalse();
        assertThat(Arrays.stream(RequestFamily.values()).filter(other -> other != family))
                .allMatch(reloaded::isEnabled);
    }

    @Test
    void familyCanBeSwitchedBackOn() {
        settings.setEnabled(RequestFamily.PING, false);
        settings.setEnabled(RequestFamily.PING, true);

        assertThat(settings.isEnabled(RequestFamily.PING)).isTrue();
    }

    @Test
    void headerFieldSwitchPersists() {
        settings.setHeaderFieldsEnabled(false);

        assertThat(new ScanGenerationSettings(store).headerFieldsEnabled()).isFalse();
    }

    @Test
    void familyIdsAreUniqueSoSwitchesNeverCollide() {
        assertThat(Arrays.stream(RequestFamily.values()).map(RequestFamily::id)).doesNotHaveDuplicates();
    }
}
