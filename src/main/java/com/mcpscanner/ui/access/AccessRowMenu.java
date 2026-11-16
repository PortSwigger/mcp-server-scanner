package com.mcpscanner.ui.access;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.AccessSnapshot;
import com.mcpscanner.access.OwnerRequests;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.ui.sendto.SendToDestination;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.function.Supplier;

final class AccessRowMenu {

    private static final String SHARED_LABEL =
            ExpectationText.label(AccessExpectation.SHARED_BY_DESIGN, ExpectationText.NEUTRAL_OWNER);

    private final AccessMatrix matrix;
    private final OwnerRequests requests;
    private final Supplier<Optional<SendToDestination>> repeater;
    private final CheckAccessControl checkAccess;
    private final Consumer<String> errors;
    private final Executor sends;

    AccessRowMenu(AccessMatrix matrix, OwnerRequests requests, Supplier<Optional<SendToDestination>> repeater,
                  CheckAccessControl checkAccess, Consumer<String> errors, Executor sends) {
        this.matrix = matrix;
        this.requests = requests;
        this.repeater = repeater;
        this.checkAccess = checkAccess;
        this.errors = errors;
        this.sends = sends;
    }

    static Executor backgroundSends() {
        return task -> {
            Thread thread = new Thread(task, "mcp-send-pair");
            thread.setDaemon(true);
            thread.start();
        };
    }

    JPopupMenu menuFor(AccessSnapshot snapshot, AccessRow row, Optional<Principal> clicked) {
        JPopupMenu menu = new JPopupMenu();
        menu.add(item("Set to “" + SHARED_LABEL + "”",
                () -> matrix.setExpectation(row.item().key(), AccessExpectation.SHARED_BY_DESIGN),
                row.expectation() == AccessExpectation.SHARED_BY_DESIGN
                        ? Optional.of("Already “" + SHARED_LABEL + "”") : Optional.empty()));
        pairTargets(snapshot, row, clicked).forEach(principal -> menu.add(item(
                "Send " + row.owner().name() + " / " + principal.name() + " pair to Repeater",
                () -> sends.execute(() -> sendPair(row, principal)), repeaterBlocker(snapshot))));
        menu.addSeparator();
        menu.add(item("Check this item", () -> checkAccess.start(List.of(row)), checkAccess.blocker()));
        return menu;
    }

    private static List<Principal> pairTargets(AccessSnapshot snapshot, AccessRow row, Optional<Principal> clicked) {
        return clicked.filter(principal -> !row.ownedBy(principal)).map(List::of)
                .orElseGet(() -> snapshot.principals().stream().filter(principal -> !row.ownedBy(principal)).toList());
    }

    private Optional<String> repeaterBlocker(AccessSnapshot snapshot) {
        if (repeater.get().isEmpty()) {
            return Optional.of("Repeater is not available");
        }
        return snapshot.connected() ? Optional.empty() : Optional.of("Connect to an MCP server first");
    }

    private void sendPair(AccessRow row, Principal principal) {
        try {
            SendToDestination destination = repeater.get().orElseThrow();
            send(destination, requests.forOwner(row), row, row.owner());
            send(destination, requests.as(row, principal), row, principal);
        } catch (RuntimeException failure) {
            errors.accept("Send to Repeater failed: " + failure.getMessage());
        }
    }

    private static void send(SendToDestination destination, HttpRequest request, AccessRow row, Principal as) {
        destination.send(request, row.item().key().name() + " as " + as.name());
    }

    private static JMenuItem item(String label, Runnable action, Optional<String> blocker) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(event -> action.run());
        item.setEnabled(blocker.isEmpty());
        blocker.ifPresent(item::setToolTipText);
        return item;
    }
}
