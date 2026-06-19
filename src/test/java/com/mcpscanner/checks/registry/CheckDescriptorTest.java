package com.mcpscanner.checks.registry;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CheckDescriptorTest {

    private static CheckDescriptor descriptor(List<String> references) {
        return new CheckDescriptor(
                "id-1", "Display Name", "desc",
                AuditIssueSeverity.MEDIUM, ScanCheckType.PER_REQUEST,
                true, references);
    }

    @Test
    void rejectsNullReferencesList() {
        assertThatThrownBy(() -> descriptor(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void rejectsNullEntryInsideReferences() {
        assertThatThrownBy(() -> descriptor(Arrays.asList("https://a", null)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsBlankEntryInsideReferences() {
        assertThatThrownBy(() -> descriptor(List.of("https://a", "   ")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void emptyReferencesListIsAccepted() {
        CheckDescriptor descriptor = descriptor(List.of());

        assertThat(descriptor.references()).isEmpty();
    }

    @Test
    void referencesListIsDefensivelyCopied() {
        List<String> mutable = new ArrayList<>();
        mutable.add("https://example.com");
        CheckDescriptor descriptor = descriptor(mutable);

        mutable.add("https://added-after");

        assertThat(descriptor.references()).containsExactly("https://example.com");
        assertThatThrownBy(() -> descriptor.references().add("https://nope"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
