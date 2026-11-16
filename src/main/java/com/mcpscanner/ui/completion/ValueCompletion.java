package com.mcpscanner.ui.completion;

import com.mcpscanner.ui.widgets.DialogOwner;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.ui.detail.RowMenu;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import java.awt.Component;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;

public final class ValueCompletion implements CompletionMenus {

    public static final String MENU_LABEL = "Ask server for values";

    private final CompletionGateway gateway;
    private final BackgroundText background;
    private final CompletionDialogs dialogs;

    ValueCompletion(CompletionGateway gateway, BackgroundText background, CompletionDialogs dialogs) {
        this.gateway = Objects.requireNonNull(gateway, "gateway");
        this.background = Objects.requireNonNull(background, "background");
        this.dialogs = Objects.requireNonNull(dialogs, "dialogs");
    }

    public static ValueCompletion forClient(McpClientManager clientManager, BooleanSupplier connectedInUi,
                                            DialogOwner owner) {
        return new ValueCompletion(new ClientCompletionGateway(clientManager, connectedInUi),
                new SwingWorkerBackgroundText(), new SwingCompletionDialogs(owner));
    }

    @Override
    public RowMenu forPromptArguments(String promptName) {
        return argument -> Optional.of(menu(CompletionTarget.forPrompt(promptName, argument)));
    }

    @Override
    public RowMenu forTemplateVariables(String uriTemplate) {
        return variable -> Optional.of(menu(CompletionTarget.forTemplate(uriTemplate, variable)));
    }

    private JPopupMenu menu(Optional<CompletionTarget> target) {
        JPopupMenu menu = new JPopupMenu();
        menu.add(target.map(found -> askItem(menu, found))
                .orElseGet(() -> item(CompletionAvailability.MALFORMED_ITEM)));
        return menu;
    }

    private JMenuItem askItem(JPopupMenu menu, CompletionTarget target) {
        JMenuItem item = item(gateway.availability());
        item.addActionListener(event -> ask(menu.getInvoker(), target));
        return item;
    }

    private static JMenuItem item(CompletionAvailability availability) {
        JMenuItem item = new JMenuItem(MENU_LABEL);
        item.setEnabled(availability.isAvailable());
        item.setToolTipText(availability.unavailableReason());
        return item;
    }

    private void ask(Component parent, CompletionTarget target) {
        dialogs.askCurrentValue(parent, target.argumentName()).ifPresent(currentValue ->
                background.run(() -> describe(target, currentValue),
                        text -> dialogs.showResult(parent, target.resultTitle(), text)));
    }

    private String describe(CompletionTarget target, String currentValue) {
        try {
            return CompletionText.render(gateway.complete(target.withCurrentValue(currentValue)));
        } catch (RuntimeException failure) {
            return CompletionText.failure(failure);
        }
    }
}
