package com.mcpscanner.ui.access;

import com.mcpscanner.access.mining.AccessMining;
import com.mcpscanner.access.mining.MiningBlocker;
import com.mcpscanner.access.mining.MiningListener;
import com.mcpscanner.access.mining.MiningReport;
import com.mcpscanner.access.mining.MiningSettings;
import com.mcpscanner.access.mining.MiningStep;
import com.mcpscanner.access.mining.WriteCallApproval;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.OwnedValueStore;
import com.mcpscanner.ui.widgets.Edt;
import com.mcpscanner.ui.widgets.PrimaryActionButton;
import com.mcpscanner.ui.widgets.ThemeColors;
import com.mcpscanner.ui.widgets.WrapLayout;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

final class MineIdsControl extends JPanel {

    static final String MINE = "Collect IDs";
    static final String MINED_IN_WRITE_TOOLS = "Use collected IDs in write tools";
    static final String TOOLTIP = "Call the server's tools as every compared user and Anonymous and collect the "
            + "IDs each one sees. Collecting sends real requests with real IDs to the server.";

    private final AccessMining mining;
    private final OwnedValueStore store;
    private final Supplier<List<Identity>> users;
    private final Runnable storeChanged = () -> Edt.run(this::minedValuesChanged);
    private final MiningConsent consent;
    private final WriteCallApproval approval;
    private final Runnable reportChanged;
    private final List<Runnable> queued = new ArrayList<>();
    private Optional<MiningReport> lastReport = Optional.empty();
    private Set<String> reportedHolders = Set.of();
    private final PrimaryActionButton mine = new PrimaryActionButton(MINE);
    private final JButton cancel = new JButton("Cancel");
    private final JLabel progress = new JLabel();
    private final JSpinner passes;
    private final WriteToolOptInControl writeTools;
    private final JCheckBox minedInWriteTools = new JCheckBox(MINED_IN_WRITE_TOOLS);

    MineIdsControl(MiningServices services, MiningConsent consent, WriteCallApproval approval,
                   Runnable reportChanged) {
        super(new BorderLayout());
        this.mining = services.mining();
        this.store = services.ownedValues();
        this.users = services.users();
        this.consent = consent;
        this.approval = approval;
        this.reportChanged = reportChanged;
        this.passes = new JSpinner(new SpinnerNumberModel(mining.preferences().passes(), MiningSettings.MIN_PASSES,
                MiningSettings.MAX_PASSES, 1));
        this.writeTools = new WriteToolOptInControl(mining, services.dialogs(), this);
        mine.setToolTipText(TOOLTIP);
        mine.addActionListener(event -> confirmThenMine());
        cancel.addActionListener(event -> mining.cancel());
        passes.addChangeListener(event -> mining.preferences().setPasses((Integer) passes.getValue()));
        minedInWriteTools.setSelected(mining.preferences().minedIdsInWriteTools());
        minedInWriteTools.setToolTipText("Off: Scan and Check access fill write tools with values you entered only. "
                + "On: collected IDs fill them too, and the write-tool confirmation lists every value and always asks.");
        minedInWriteTools.addActionListener(event ->
                mining.preferences().setMinedIdsInWriteTools(minedInWriteTools.isSelected()));
        progress.setForeground(ThemeColors.muted());
        add(controls(), BorderLayout.NORTH);
        store.addListener(storeChanged);
        refresh();
    }

    void dispose() {
        store.removeListener(storeChanged);
    }

    void mine(Runnable afterwards) {
        if (mining.start(new Progress(), approval).isPresent()) {
            queued.clear();
            queued.add(afterwards);
            clearReport();
            progress.setText("Collecting…");
        }
        refresh();
    }

    void afterCurrentRun(Runnable action) {
        queued.add(action);
    }

    Optional<MiningReport> lastReport() {
        return lastReport;
    }

    Set<String> usersWithoutIds() {
        return lastReport.map(MiningReport::usersWithoutIds).orElse(Set.of());
    }

    private void confirmThenMine() {
        if (consent.confirmMining(this)) {
            mine(() -> { });
        }
    }

    void refresh() {
        boolean running = mining.running();
        Optional<String> blocker = mining.blocker().map(MineIdsControl::blockerText);
        mine.setEnabled(blocker.isEmpty());
        mine.setToolTipText(blocker.orElse(TOOLTIP));
        cancel.setEnabled(running);
        passes.setEnabled(!running);
        writeTools.choice().setEnabled(!running);
    }

    PrimaryActionButton mineButton() {
        return mine;
    }

    JButton cancelButton() {
        return cancel;
    }

    JLabel progress() {
        return progress;
    }

    JSpinner passes() {
        return passes;
    }

    JCheckBox minedInWriteTools() {
        return minedInWriteTools;
    }

    WriteToolOptInControl writeTools() {
        return writeTools;
    }

    private JPanel controls() {
        JPanel row = new JPanel(new WrapLayout(FlowLayout.LEADING, 8, 4));
        row.add(mine);
        row.add(cancel);
        row.add(progress);
        row.add(new JLabel("Passes:"));
        row.add(passes);
        row.add(new JLabel("Write tools:"));
        row.add(writeTools.choice());
        row.add(writeTools.chooseButton());
        row.add(minedInWriteTools);
        return row;
    }

    private static String blockerText(MiningBlocker blocker) {
        return switch (blocker) {
            case NOT_CONNECTED -> "Connect to an MCP server first";
            case RUNNING -> "Collecting IDs is already running";
        };
    }

    private void minedValuesChanged() {
        if (!minedHolders().containsAll(reportedHolders)) {
            clearReport();
            progress.setText("");
        }
    }

    private void clearReport() {
        lastReport = Optional.empty();
        reportedHolders = Set.of();
        reportChanged.run();
    }

    private Set<String> minedHolders() {
        return users.get().stream().filter(user -> !user.ownedValues().mined().isEmpty()).map(Identity::id)
                .collect(Collectors.toUnmodifiableSet());
    }

    private void finish(MiningReport finished) {
        lastReport = Optional.of(finished);
        reportedHolders = minedHolders();
        progress.setText(finished.summary());
        refresh();
        reportChanged.run();
        List<Runnable> continuations = List.copyOf(queued);
        queued.clear();
        if (finished.stop().completed()) {
            continuations.forEach(Runnable::run);
        }
    }

    private final class Progress implements MiningListener {

        @Override
        public void progressed(String user, MiningStep step) {
            Edt.run(() -> progress.setText("Collecting as " + user + ": pass " + step.pass() + ", "
                    + step.requestsSent() + " requests"));
        }

        @Override
        public void finished(MiningReport finished) {
            Edt.run(() -> finish(finished));
        }
    }
}
