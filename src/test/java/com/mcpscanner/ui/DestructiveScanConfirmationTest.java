package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.DialogOwner;
import org.junit.jupiter.api.Test;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import java.awt.Component;
import java.awt.GraphicsEnvironment;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class DestructiveScanConfirmationTest {

    private static final DestructiveScanConfirmation.Lines LINES = new DestructiveScanConfirmation.Lines(
            "lead", "count", List.of("tool"), DestructiveScanConfirmation.Purpose.SCAN);

    @Test
    void theLeadTextNamesWhatInvokesTheTools() {
        assertThat(DestructiveScanConfirmation.leadText("The extension's checks"))
                .isEqualTo("The extension's checks will invoke these tools with attacker-controlled inputs. "
                        + "This can modify, create, or delete data on the target — irreversible.");
    }

    @Test
    void withNoParentTheDialogIsOwnedByBurpsSuiteFrame() {
        assertOwnedBySuiteFrame(null);
    }

    @Test
    void withAParentOutsideAnyWindowTheDialogIsOwnedByBurpsSuiteFrame() {
        assertOwnedBySuiteFrame(new JPanel());
    }

    private static void assertOwnedBySuiteFrame(Component parent) {
        assumeFalse(GraphicsEnvironment.isHeadless());
        JFrame suiteFrame = new JFrame();
        JDialog dialog = DestructiveScanConfirmation.dialog(new DialogOwner(() -> suiteFrame), parent, LINES);
        try {
            assertThat(dialog.getOwner()).isSameAs(suiteFrame);
        } finally {
            dialog.dispose();
            suiteFrame.dispose();
        }
    }
}
