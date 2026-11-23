package com.mcpscanner.ui;

import com.mcpscanner.scan.ScanGenerationSettings;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.RequestFamilyGroup;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.widgets.ToggleGroupCard;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class RequestFamiliesPanelTest {

    private final ScanGenerationSettings settings = new ScanGenerationSettings(InMemoryPersistedObject.configStore());

    @Test
    void showsOneTickedBoxPerFamilyAndTheHeaderSwitch() {
        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);

        for (RequestFamily family : RequestFamily.values()) {
            assertThat(box(panel, family).isSelected()).as(family.name()).isTrue();
        }
        assertThat(box(panel, RequestFamiliesPanel.HEADER_FIELDS_LABEL).isSelected()).isTrue();
    }

    @Test
    void familyLabelsAreUniqueSoEachBoxIsUnambiguous() {
        assertThat(Arrays.stream(RequestFamily.values()).map(RequestFamily::label)).doesNotHaveDuplicates();
    }

    @ParameterizedTest
    @EnumSource(RequestFamilyGroup.class)
    void everyGroupHasATickedMasterBox(RequestFamilyGroup group) {
        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);

        assertThat(box(panel, group.title()).isSelected()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(RequestFamily.class)
    void untickingABoxSwitchesThatFamilyOff(RequestFamily family) {
        box(new RequestFamiliesPanel(settings), family).doClick();

        assertThat(settings.isEnabled(family)).isFalse();
    }

    @Test
    void untickingTheHeaderBoxSwitchesHeaderFieldsOff() {
        box(new RequestFamiliesPanel(settings), RequestFamiliesPanel.HEADER_FIELDS_LABEL).doClick();

        assertThat(settings.headerFieldsEnabled()).isFalse();
    }

    @Test
    void showsAnUntickedMetaEnvelopeSwitchThatTurnsFuzzingOnEveryRequestOn() {
        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);
        AbstractButton metaBox = box(panel, RequestFamiliesPanel.META_ENVELOPE_LABEL);

        assertThat(metaBox.isSelected()).isFalse();
        metaBox.doClick();

        assertThat(settings.metaEnvelopeFuzzedOnEveryRequest()).isTrue();
    }

    @Test
    void untickingAGroupMasterSwitchesOnlyThatGroupOff() {
        box(new RequestFamiliesPanel(settings), RequestFamilyGroup.NOTIFICATIONS.title()).doClick();

        for (RequestFamily family : RequestFamily.values()) {
            assertThat(settings.isEnabled(family)).as(family.name())
                    .isEqualTo(family.group() != RequestFamilyGroup.NOTIFICATIONS);
        }
    }

    @Test
    void aPartlyTickedGroupShowsItsMasterAsIndeterminate() {
        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);

        box(panel, RequestFamily.PING).doClick();

        JCheckBox master = box(panel, RequestFamilyGroup.LIFECYCLE.title());
        assertThat(master.isSelected()).isFalse();
        assertThat(master.getClientProperty(ToggleGroupCard.SELECTED_STATE)).isEqualTo(ToggleGroupCard.INDETERMINATE);
    }

    @Test
    void retickingTheLastFamilyClearsTheIndeterminateMaster() {
        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);

        box(panel, RequestFamily.PING).doClick();
        box(panel, RequestFamily.PING).doClick();

        JCheckBox master = box(panel, RequestFamilyGroup.LIFECYCLE.title());
        assertThat(master.isSelected()).isTrue();
        assertThat(master.getClientProperty(ToggleGroupCard.SELECTED_STATE)).isNull();
    }

    @Test
    void clickingAnIndeterminateMasterTicksTheWholeGroup() {
        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);
        box(panel, RequestFamily.PING).doClick();

        box(panel, RequestFamilyGroup.LIFECYCLE.title()).doClick();

        assertThat(settings.isEnabled(RequestFamily.PING)).isTrue();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {RequestFamiliesPanel.SELECT_ALL, RequestFamiliesPanel.SELECT_NONE})
    void selectionShortcutsLookLikeButtonsNotHeadings(String label) {
        JButton shortcut = button(new RequestFamiliesPanel(settings), label);

        assertThat(shortcut.getClientProperty("JButton.buttonType")).isNull();
        assertThat(shortcut.isBorderPainted()).isTrue();
        assertThat(shortcut.getFont().isBold()).isFalse();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(ints = {300, 560, 900})
    void theScrollableFormIsTallEnoughForEveryGroupAndTheHeaderSwitch(int width) throws Exception {
        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);
        panel.setSize(width, 300);
        for (int pass = 0; pass < 4; pass++) {
            layOut(panel);
            javax.swing.SwingUtilities.invokeAndWait(() -> { });
        }

        javax.swing.JViewport viewport = SwingTree.descendants(panel).stream()
                .filter(javax.swing.JViewport.class::isInstance).map(javax.swing.JViewport.class::cast)
                .findFirst().orElseThrow();
        java.awt.Component form = viewport.getView();
        JCheckBox lastOption = box(panel, RequestFamiliesPanel.HEADER_FIELDS_LABEL);
        java.awt.Rectangle inForm = javax.swing.SwingUtilities.convertRectangle(lastOption.getParent(),
                lastOption.getBounds(), form);
        assertThat(inForm.y + inForm.height).isLessThanOrEqualTo(form.getHeight());
        for (RequestFamily family : RequestFamily.values()) {
            JCheckBox option = box(panel, family);
            java.awt.Rectangle bounds = javax.swing.SwingUtilities.convertRectangle(option.getParent(),
                    option.getBounds(), form);
            assertThat(bounds.y + bounds.height).as(family.name()).isLessThanOrEqualTo(form.getHeight());
        }
    }

    private static void layOut(java.awt.Container container) {
        container.doLayout();
        for (java.awt.Component child : container.getComponents()) {
            if (child instanceof java.awt.Container nested) {
                layOut(nested);
            }
        }
    }

    @Test
    void selectNoneSwitchesEveryFamilyOffButLeavesHeaderFields() {
        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);

        button(panel, RequestFamiliesPanel.SELECT_NONE).doClick();

        assertThat(RequestFamily.values()).noneMatch(settings::isEnabled);
        assertThat(settings.headerFieldsEnabled()).isTrue();
        assertThat(box(panel, RequestFamily.TOOLS_CALL).isSelected()).isFalse();
    }

    @Test
    void selectAllSwitchesEveryFamilyBackOn() {
        Arrays.stream(RequestFamily.values()).forEach(family -> settings.setEnabled(family, false));
        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);

        button(panel, RequestFamiliesPanel.SELECT_ALL).doClick();

        assertThat(RequestFamily.values()).allMatch(settings::isEnabled);
        assertThat(box(panel, RequestFamilyGroup.LISTING.title()).isSelected()).isTrue();
    }

    @Test
    void reflectsPersistedState() {
        settings.setEnabled(RequestFamily.SERVER_DISCOVER, false);
        settings.setHeaderFieldsEnabled(false);

        RequestFamiliesPanel panel = new RequestFamiliesPanel(settings);

        assertThat(box(panel, RequestFamily.SERVER_DISCOVER).isSelected()).isFalse();
        assertThat(box(panel, RequestFamiliesPanel.HEADER_FIELDS_LABEL).isSelected()).isFalse();
        assertThat(box(panel, RequestFamilyGroup.LIFECYCLE.title()).getClientProperty(ToggleGroupCard.SELECTED_STATE))
                .isEqualTo(ToggleGroupCard.INDETERMINATE);
    }

    private static JCheckBox box(RequestFamiliesPanel panel, RequestFamily family) {
        return box(panel, family.label());
    }

    private static JCheckBox box(RequestFamiliesPanel panel, String label) {
        return (JCheckBox) labelled(panel, JCheckBox.class, label);
    }

    private static JButton button(RequestFamiliesPanel panel, String label) {
        return (JButton) labelled(panel, JButton.class, label);
    }

    private static AbstractButton labelled(RequestFamiliesPanel panel, Class<? extends AbstractButton> type,
                                           String label) {
        return SwingTree.descendants(panel).stream()
                .filter(type::isInstance).map(AbstractButton.class::cast)
                .filter(button -> label.equals(button.getText()))
                .findFirst().orElseThrow();
    }
}
