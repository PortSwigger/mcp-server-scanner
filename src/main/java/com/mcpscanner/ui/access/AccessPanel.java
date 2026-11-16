package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessSnapshot;
import com.mcpscanner.access.WriteReplayApproval;
import com.mcpscanner.access.mining.WriteCallApproval;
import com.mcpscanner.ui.sendto.SendToDestination;
import com.mcpscanner.ui.widgets.TitledPanel;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Supplier;

public final class AccessPanel extends JPanel implements TitledPanel {

    static final String EMPTY_CARD = "needs-identities";
    static final String MATRIX_CARD = "matrix";
    private static final String TITLE = "Access";

    private final AccessServices services;
    private final CardLayout cards = new CardLayout();
    private final JPanel cardPanel = new JPanel(cards);
    private final AccessEmptyState emptyState = new AccessEmptyState();
    private final CheckAccessControl checkAccess;
    private final AccessMatrixView matrixView;
    private final Optional<MiningSection> mining;
    private final AtomicBoolean refreshQueued = new AtomicBoolean();
    private final Runnable matrixChanged = this::queueRefresh;
    private Runnable titleChanged = () -> { };
    private String title = TITLE;
    private String visibleCard = MATRIX_CARD;

    public AccessPanel(AccessServices services, WriteReplayApproval approval,
                       Supplier<Optional<SendToDestination>> repeater, Consumer<String> errors) {
        this(services, new AccessApprovals(approval, WriteCallApproval.REFUSE), repeater, errors);
    }

    public AccessPanel(AccessServices services, AccessApprovals approvals,
                       Supplier<Optional<SendToDestination>> repeater, Consumer<String> errors) {
        super(new BorderLayout());
        this.services = services;
        this.checkAccess = new CheckAccessControl(services.runner(), approvals.replays());
        AccessTableModel model = new AccessTableModel(services.matrix()::setExpectation);
        this.matrixView = new AccessMatrixView(model, checkAccess,
                new AccessRowMenu(services.matrix(), services.requests(), repeater, checkAccess, errors,
                        AccessRowMenu.backgroundSends()),
                services.refreshListings());
        this.mining = services.mining().map(mined -> new MiningSection(mined, approvals.miningWrites(), this,
                this::queueRefresh));
        cardPanel.add(emptyState, EMPTY_CARD);
        cardPanel.add(matrixView, MATRIX_CARD);
        mining.ifPresentOrElse(this::layOutWithMining, () -> add(cardPanel, BorderLayout.CENTER));
        mining.ifPresent(section -> checkAccess.gateLaunches(section.mineFirst()));
        services.matrix().addListener(matrixChanged);
        refresh();
    }

    public LaunchGate mineFirst() {
        return mining.map(MiningSection::mineFirst).orElse(LaunchGate.DIRECT);
    }

    private void layOutWithMining(MiningSection section) {
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, cardPanel, section.values());
        split.setResizeWeight(0.7);
        add(section.control(), BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    public void setIdentityShortcuts(IdentityShortcuts shortcuts) {
        emptyState.setShortcuts(shortcuts);
        checkAccess.noComparisonHint().setShortcuts(shortcuts);
    }

    @Override
    public void onTitleChange(Runnable listener) {
        titleChanged = listener;
    }

    @Override
    public String title() {
        return title;
    }

    public void dispose() {
        services.matrix().removeListener(matrixChanged);
        checkAccess.cancel();
        mining.ifPresent(MiningSection::dispose);
    }

    private void queueRefresh() {
        if (refreshQueued.compareAndSet(false, true)) {
            SwingUtilities.invokeLater(() -> {
                refreshQueued.set(false);
                refresh();
            });
        }
    }

    void refresh() {
        AccessSnapshot snapshot = services.matrix().snapshot();
        visibleCard = services.otherUserCount().getAsInt() == 0 ? EMPTY_CARD : MATRIX_CARD;
        cards.show(cardPanel, visibleCard);
        matrixView.show(snapshot, mining.map(MiningSection::usersWithoutIds).orElse(Set.of()));
        mining.ifPresent(MiningSection::refresh);
        updateTitle(snapshot.issues());
    }

    String visibleCard() {
        return visibleCard;
    }

    AccessMatrixView matrixView() {
        return matrixView;
    }

    Optional<MiningSection> mining() {
        return mining;
    }

    AccessEmptyState emptyState() {
        return emptyState;
    }

    private void updateTitle(long issues) {
        String next = issues == 0 ? TITLE : TITLE + " (" + issues + (issues == 1 ? " issue)" : " issues)");
        if (!next.equals(title)) {
            title = next;
            titleChanged.run();
        }
    }
}
