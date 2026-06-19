package com.mcpscanner.auth.oauth.safety;

import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.Test;

import java.awt.Frame;
import java.awt.GraphicsEnvironment;
import java.awt.Window;
import java.util.function.Supplier;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.mockito.Mockito.mock;

class SuspiciousDestinationConfirmerTest {

    @Test
    void resolvesTheParentWindowProvidedBySupplier() {
        Window mockWindow = mock(Window.class);

        SuspiciousDestinationConfirmer.SwingConfirmer confirmer = swingConfirmer(() -> mockWindow);

        assertThat(confirmer.resolveParent()).isSameAs(mockWindow);
    }

    @Test
    void resolvesNullParentWhenSupplierAbsent() {
        SuspiciousDestinationConfirmer.SwingConfirmer confirmer = swingConfirmer(() -> null);

        assertThatNoException().isThrownBy(() -> assertThat(confirmer.resolveParent()).isNull());
    }

    @Test
    void resolvesNullParentWhenSupplierReturnsNull() {
        SuspiciousDestinationConfirmer.SwingConfirmer confirmer = swingConfirmer(() -> null);

        assertThat(confirmer.resolveParent()).isNull();
    }

    @Test
    void dialogIsOwnedByTheSuppliedParentWindow() {
        assumeFalse(GraphicsEnvironment.isHeadless(), "requires a display");

        JFrame parent = new JFrame();
        try {
            SuspiciousDestinationConfirmer.SwingConfirmer confirmer = swingConfirmer(() -> parent);

            JDialog dialog = confirmer.createDialog(confirmer.resolveParent(), pane());

            assertThat(dialog.getOwner()).isSameAs(parent);
        } finally {
            parent.dispose();
        }
    }

    @Test
    void dialogWithNullParentFallsBackToSharedHiddenOwnerFrame() {
        assumeFalse(GraphicsEnvironment.isHeadless(), "requires a display");

        SuspiciousDestinationConfirmer.SwingConfirmer confirmer = swingConfirmer(() -> null);

        JDialog dialog = confirmer.createDialog(confirmer.resolveParent(), pane());

        // A null-parent JDialog gets Swing's shared hidden owner frame, never a supplied window.
        assertThat(dialog.getOwner()).isInstanceOf(Frame.class);
    }

    private static SuspiciousDestinationConfirmer.SwingConfirmer swingConfirmer(Supplier<Window> parentSupplier) {
        return (SuspiciousDestinationConfirmer.SwingConfirmer)
                SuspiciousDestinationConfirmer.swing(McpEventLog.noop(), parentSupplier);
    }

    private static JOptionPane pane() {
        return new JOptionPane("test", JOptionPane.WARNING_MESSAGE, JOptionPane.YES_NO_OPTION);
    }
}
