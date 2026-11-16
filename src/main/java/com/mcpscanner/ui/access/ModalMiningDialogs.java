package com.mcpscanner.ui.access;

import com.mcpscanner.identity.EnteredValue;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.ui.widgets.DialogOwner;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;

import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

final class ModalMiningDialogs implements MiningDialogs {

    static final String MINE_FIRST_TITLE = "Collect IDs first?";
    static final String MINE_FIRST_BODY = "IDs have not been collected for these users on this connection, so requests "
            + "will carry schema defaults instead of real IDs.";

    private final DialogOwner owner;

    ModalMiningDialogs(DialogOwner owner) {
        this.owner = Objects.requireNonNull(owner, "owner");
    }

    @Override
    public MineFirstChoice mineFirst(Component parent, ToolsToCall tools) {
        Object[] options = {"Collect", "Continue without", "Cancel"};
        int chosen = JOptionPane.showOptionDialog(owner.of(parent), MiningSummary.withLead(MINE_FIRST_BODY, tools),
                MINE_FIRST_TITLE, JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, options,
                options[0]);
        return switch (chosen) {
            case 0 -> MineFirstChoice.MINE;
            case 1 -> MineFirstChoice.CONTINUE_WITHOUT;
            default -> MineFirstChoice.CANCEL;
        };
    }

    @Override
    public boolean confirmMining(Component parent, ToolsToCall tools) {
        Object[] options = {"Collect", "Cancel"};
        return JOptionPane.showOptionDialog(owner.of(parent), MiningSummary.of(tools), "Collect IDs?",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[1]) == 0;
    }

    @Override
    public ClearChoice clearMined(Component parent, String userName) {
        Object[] options = {"Clear for " + userName, "Clear for all users", "Cancel"};
        int chosen = JOptionPane.showOptionDialog(owner.of(parent), "Delete collected IDs? Values you entered are kept.",
                "Clear collected IDs", JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE, null,
                options, options[2]);
        return switch (chosen) {
            case 0 -> ClearChoice.THIS_USER;
            case 1 -> ClearChoice.ALL_USERS;
            default -> ClearChoice.CANCEL;
        };
    }

    @Override
    public Optional<EnteredValue> enterValue(Component parent, Optional<EnteredValue> current) {
        JTextField argument = new JTextField(current.map(EnteredValue::argument).orElse(""), 24);
        JTextField value = new JTextField(current.map(EnteredValue::value).orElse(""), 24);
        JPanel form = new JPanel(new GridLayout(0, 2, 6, 6));
        form.add(new JLabel("Argument"));
        form.add(argument);
        form.add(new JLabel("Value"));
        form.add(value);
        int chosen = JOptionPane.showConfirmDialog(owner.of(parent), form, current.isPresent() ? "Edit value" : "Add value",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        boolean complete = !argument.getText().isBlank() && !value.getText().isBlank();
        return chosen == JOptionPane.OK_OPTION && complete
                ? Optional.of(new EnteredValue(argument.getText().trim(), value.getText().trim())) : Optional.empty();
    }

    @Override
    public Optional<Set<String>> chooseWriteTools(Component parent, List<McpToolDefinition> tools,
                                                  Set<String> selected) {
        JPanel list = new JPanel();
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        List<JCheckBox> boxes = tools.stream().map(tool -> checkBox(tool, selected)).toList();
        boxes.forEach(list::add);
        JScrollPane scroller = new JScrollPane(list);
        scroller.setPreferredSize(new Dimension(360, Math.min(240, 28 * Math.max(3, tools.size()))));
        int chosen = JOptionPane.showConfirmDialog(owner.of(parent), scroller, "Write tools collecting may call",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (chosen != JOptionPane.OK_OPTION) {
            return Optional.empty();
        }
        Set<String> picked = new LinkedHashSet<>();
        boxes.stream().filter(JCheckBox::isSelected).forEach(box -> picked.add(box.getText()));
        return Optional.of(picked);
    }

    private static JCheckBox checkBox(McpToolDefinition tool, Set<String> selected) {
        JCheckBox box = new JCheckBox(tool.name(), selected.contains(tool.name()));
        SwingHtmlGuard.disableHtml(box);
        return box;
    }
}
