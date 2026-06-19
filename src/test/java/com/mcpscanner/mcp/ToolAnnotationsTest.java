package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ToolAnnotationsTest {

    @Test
    void classifyReadOnly_whenReadOnlyHintTrue() {
        ToolAnnotations annotations = new ToolAnnotations(null, true, null, null, null);

        assertThat(annotations.classify()).isEqualTo(ToolAnnotations.Display.READ_ONLY);
    }

    @Test
    void classifyNotSpecified_whenAllFieldsNull() {
        ToolAnnotations annotations = new ToolAnnotations(null, null, null, null, null);

        assertThat(annotations.classify()).isEqualTo(ToolAnnotations.Display.NOT_SPECIFIED);
    }

    @Test
    void classifyDestructive_whenReadOnlyHintFalseExplicit() {
        ToolAnnotations annotations = new ToolAnnotations(null, false, null, null, null);

        assertThat(annotations.classify()).isEqualTo(ToolAnnotations.Display.DESTRUCTIVE);
    }

    @Test
    void classifyDestructive_whenReadOnlyHintNullButOtherFieldsPresent() {
        ToolAnnotations annotations = new ToolAnnotations(null, null, true, null, null);

        assertThat(annotations.classify()).isEqualTo(ToolAnnotations.Display.DESTRUCTIVE);
    }

    @Test
    void isExplicitlyReadOnly_falseForExplicitFalse() {
        ToolAnnotations explicitFalse = new ToolAnnotations(null, false, null, null, null);
        ToolAnnotations absent = new ToolAnnotations(null, null, null, null, null);

        assertThat(explicitFalse.isExplicitlyReadOnly()).isFalse();
        assertThat(absent.isExplicitlyReadOnly()).isFalse();
    }

    @Test
    void EMPTY_isAbsent() {
        assertThat(ToolAnnotations.EMPTY.isAbsent()).isTrue();
        assertThat(ToolAnnotations.EMPTY.classify()).isEqualTo(ToolAnnotations.Display.NOT_SPECIFIED);
    }
}
