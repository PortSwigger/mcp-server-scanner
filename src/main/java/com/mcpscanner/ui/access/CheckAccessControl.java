package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.AccessRun;
import com.mcpscanner.access.AccessRunListener;
import com.mcpscanner.access.AccessRunSummary;
import com.mcpscanner.access.AccessSnapshot;
import com.mcpscanner.access.CheckAccessRunner;
import com.mcpscanner.access.WriteReplayApproval;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.SyntheticLabel;
import com.mcpscanner.ui.widgets.Edt;
import com.mcpscanner.ui.widgets.PrimaryActionButton;
import com.mcpscanner.ui.widgets.ThemeColors;

import javax.swing.JLabel;
import java.util.List;
import java.util.Optional;

final class CheckAccessControl {

    static final String LABEL = "Check access";

    private final CheckAccessRunner runner;
    private final WriteReplayApproval approval;
    private final PrimaryActionButton button = new PrimaryActionButton(LABEL);
    private final JLabel scope = new JLabel();
    private final NoComparisonHint noComparisonHint = new NoComparisonHint();
    private Optional<AccessRun> current = Optional.empty();
    private List<AccessRow> visibleRows = List.of();
    private Optional<String> blocker = Optional.empty();
    private LaunchGate launchGate = LaunchGate.DIRECT;

    CheckAccessControl(CheckAccessRunner runner, WriteReplayApproval approval) {
        this.runner = runner;
        this.approval = approval;
        scope.setForeground(ThemeColors.muted());
        button.addActionListener(event -> startOrCancel());
    }

    PrimaryActionButton button() {
        return button;
    }

    JLabel scope() {
        return scope;
    }

    NoComparisonHint noComparisonHint() {
        return noComparisonHint;
    }

    void gateLaunches(LaunchGate gate) {
        launchGate = gate;
    }

    boolean running() {
        return current.isPresent();
    }

    Optional<String> blocker() {
        return running() ? Optional.of("A check is already running") : blocker;
    }

    void show(AccessSnapshot snapshot, List<AccessRow> rows) {
        visibleRows = rows;
        blocker = CheckAccessReadiness.blocker(snapshot, rows);
        showScope(snapshot, rows);
        if (!running()) {
            showIdle();
        }
    }

    void start(List<AccessRow> rows) {
        if (blocker().isPresent()) {
            return;
        }
        current = runner.start(rows, approval, new ButtonProgress());
        current.ifPresent(run -> showProgress(0, rows.size()));
    }

    void cancel() {
        current.ifPresent(AccessRun::cancel);
    }

    private void startOrCancel() {
        if (running()) {
            cancel();
        } else {
            launchGate.run(() -> start(visibleRows));
        }
    }

    private void showScope(AccessSnapshot snapshot, List<AccessRow> rows) {
        List<Principal> compared = snapshot.comparedIdentities();
        scope.setText(primaryPrincipal(snapshot).filter(principal -> !compared.isEmpty())
                .map(principal -> CheckAccessScope.describe(rows.size(), principal, compared)).orElse(""));
        scope.setVisible(!scope.getText().isEmpty());
        noComparisonHint.setVisible(CheckAccessReadiness.suggestsComparing(snapshot));
    }

    private static Optional<Principal> primaryPrincipal(AccessSnapshot snapshot) {
        return snapshot.principals().stream()
                .filter(principal -> principal.id().equals(Principal.PRIMARY_ID)).findFirst();
    }

    private void showIdle() {
        button.setText(LABEL);
        button.setPrimary(true);
        button.setEnabled(blocker.isEmpty());
        button.setToolTipText(blocker.orElse("Replay each item as every compared user, " + SyntheticLabel.ALWAYS_COMPARED
                + ", and compare"));
    }

    private void showProgress(int done, int total) {
        button.setText("Cancel check (" + done + "/" + total + ")");
        button.setPrimary(false);
        button.setEnabled(true);
        button.setToolTipText("Stop after the items being checked");
    }

    private final class ButtonProgress implements AccessRunListener {
        @Override
        public void progress(int done, int total) {
            Edt.run(() -> {
                if (running()) {
                    showProgress(done, total);
                }
            });
        }

        @Override
        public void finished(AccessRunSummary summary) {
            Edt.run(() -> {
                current = Optional.empty();
                showIdle();
            });
        }
    }
}
