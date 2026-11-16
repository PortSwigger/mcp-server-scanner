package com.mcpscanner.ui.widgets;

import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import java.awt.Frame;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class DialogOwnerTest {

    private final Frame suiteFrame = mock(Frame.class);
    private final DialogOwner owner = new DialogOwner(() -> suiteFrame);

    @Test
    void aMissingParentIsOwnedByBurpsSuiteFrame() {
        assertThat(owner.of(null)).isSameAs(suiteFrame);
    }

    @Test
    void aParentOutsideAnyWindowIsOwnedByBurpsSuiteFrame() {
        assertThat(owner.of(new JPanel())).isSameAs(suiteFrame);
    }

    @Test
    void aParentThatIsAWindowOwnsItsOwnDialogs() {
        Frame detached = mock(Frame.class);

        assertThat(owner.of(detached)).isSameAs(detached);
    }
}
