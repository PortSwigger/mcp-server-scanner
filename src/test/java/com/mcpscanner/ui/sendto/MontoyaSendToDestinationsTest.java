package com.mcpscanner.ui.sendto;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.comparer.Comparer;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.decoder.Decoder;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.Intruder;
import burp.api.montoya.organizer.Organizer;
import burp.api.montoya.repeater.Repeater;
import com.mcpscanner.mcp.ScannerSentinels;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class MontoyaSendToDestinationsTest {

    private final MontoyaApi api = mock(MontoyaApi.class);
    private final Repeater repeater = mock(Repeater.class);
    private final Intruder intruder = mock(Intruder.class);
    private final Organizer organizer = mock(Organizer.class);
    private final Comparer comparer = mock(Comparer.class);
    private final Decoder decoder = mock(Decoder.class);
    private final HttpRequest request = mock(HttpRequest.class);
    private final ByteArray requestBytes = mock(ByteArray.class);
    private final HttpRequest scannerFramed = mock(HttpRequest.class);
    private final HttpRequest unframed = mock(HttpRequest.class);
    private final ByteArray unframedBytes = mock(ByteArray.class);
    private List<SendToDestination> destinations;

    @BeforeEach
    void setUp() {
        when(api.repeater()).thenReturn(repeater);
        when(api.intruder()).thenReturn(intruder);
        when(api.organizer()).thenReturn(organizer);
        when(api.comparer()).thenReturn(comparer);
        when(api.decoder()).thenReturn(decoder);
        when(request.toByteArray()).thenReturn(requestBytes);
        when(scannerFramed.hasHeader(ScannerSentinels.FRAMED_OPERATION_HEADER)).thenReturn(true);
        when(scannerFramed.withRemovedHeader(ScannerSentinels.FRAMED_OPERATION_HEADER)).thenReturn(unframed);
        when(unframed.toByteArray()).thenReturn(unframedBytes);
        destinations = MontoyaSendToDestinations.create(api);
    }

    @Test
    void listsEveryBurpDestinationTheApiSupports() {
        assertThat(destinations).extracting(SendToDestination::name)
                .containsExactly("Repeater", "Intruder", "Organizer", "Comparer", "Decoder");
    }

    @Test
    void repeaterReceivesRequestAndTitle() {
        destination("Repeater").send(request, "Tool: echo");

        verify(repeater).sendToRepeater(request, "Tool: echo");
    }

    @Test
    void intruderReceivesRequestAndTitle() {
        destination("Intruder").send(request, "Tool: echo");

        verify(intruder).sendToIntruder(request, "Tool: echo");
    }

    @Test
    void organizerReceivesRequest() {
        destination("Organizer").send(request, "Tool: echo");

        verify(organizer).sendToOrganizer(request);
    }

    @Test
    void comparerReceivesRequestBytes() {
        destination("Comparer").send(request, "Tool: echo");

        verify(comparer).sendToComparer(requestBytes);
    }

    @Test
    void decoderReceivesRequestBytes() {
        destination("Decoder").send(request, "Tool: echo");

        verify(decoder).sendToDecoder(requestBytes);
        verifyNoMoreInteractions(repeater, intruder, organizer);
    }

    @Test
    void repeaterItemsCarryNoScannerFramingSentinelThatAResendWithoutTheExtensionWouldLeak() {
        destination("Repeater").send(scannerFramed, "Tool: echo");

        verify(repeater).sendToRepeater(unframed, "Tool: echo");
    }

    @Test
    void organizerItemsCarryNoScannerFramingSentinel() {
        destination("Organizer").send(scannerFramed, "Tool: echo");

        verify(organizer).sendToOrganizer(unframed);
    }

    @Test
    void intruderComparerAndDecoderReceiveNoScannerFramingSentinel() {
        destination("Intruder").send(scannerFramed, "Tool: echo");
        destination("Comparer").send(scannerFramed, "Tool: echo");
        destination("Decoder").send(scannerFramed, "Tool: echo");

        verify(intruder).sendToIntruder(unframed, "Tool: echo");
        verify(comparer).sendToComparer(unframedBytes);
        verify(decoder).sendToDecoder(unframedBytes);
    }

    private SendToDestination destination(String name) {
        return destinations.stream().filter(d -> d.name().equals(name)).findFirst().orElseThrow();
    }
}
