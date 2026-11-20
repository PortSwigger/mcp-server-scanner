package com.mcpscanner.checks.shared.stream;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class StreamEvidenceNoteTest {

    @Test
    void coversEveryRequestWhenAllWentOutsideBurp() {
        assertThat(StreamEvidenceNote.sentOutsideBurp(List.of("the baseline request", "the control request"), 2))
                .hasValueSatisfying(note -> assertThat(note)
                        .startsWith("The scanner sent these requests with its own HTTP client, outside Burp"));
    }

    @Test
    void namesOnlyTheRequestsThatWentOutsideBurp() {
        assertThat(StreamEvidenceNote.sentOutsideBurp(List.of("the probe", "the control request"), 3))
                .hasValueSatisfying(note -> assertThat(note)
                        .startsWith("The scanner sent the probe and the control request with its own HTTP client"));
    }

    @Test
    void namesASingleRequestOnItsOwn() {
        assertThat(StreamEvidenceNote.sentOutsideBurp(List.of("the control request"), 3))
                .hasValueSatisfying(note -> assertThat(note)
                        .startsWith("The scanner sent the control request with its own HTTP client"));
    }

    @Test
    void claimsAnEventStreamReplyOnlyWhereTheServerAnsweredWithOne() {
        assertThat(StreamEvidenceNote.sentOutsideBurp(List.of("the control request"), 1))
                .hasValueSatisfying(note -> assertThat(note)
                        .contains("where the server answered with an event stream")
                        .doesNotContain("the event stream that answered it"));
    }

    @Test
    void saysTheEvidenceIsTheEventStreamAsReceived() {
        assertThat(StreamEvidenceNote.sentOutsideBurp(List.of("the probe"), 1))
                .hasValueSatisfying(note -> assertThat(note)
                        .contains("the evidence response is the event stream exactly as received, up to the "
                                + "JSON-RPC reply the scanner read from it."));
    }

    @Test
    void saysNothingWhenNoRequestWentOutsideBurp() {
        assertThat(StreamEvidenceNote.sentOutsideBurp(List.of(), 3)).isEmpty();
    }
}
