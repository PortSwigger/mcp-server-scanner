package com.mcpscanner.ui.identities;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityRole;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class IdentityTableModel extends AbstractTableModel {

    static final int COMPARE = 0;
    static final int NAME = 1;
    static final int ACCESS = 2;
    static final int AUTH = 3;
    static final int STATUS = 4;
    static final int COLUMN_COUNT = 5;
    static final String ALWAYS_INCLUDED = "Always included";
    static final String NO_ACCESS_LEVEL = "—";
    private static final String[] COLUMNS = {"Compare", "Name", "Access", "Auth", "Status"};

    private final IdentityUiServices services;
    private final IdentityStatusText status;
    private final IdentityCommands commands;
    private List<IdentityRow> rows = List.of();

    IdentityTableModel(IdentityUiServices services, IdentityCommands commands) {
        this.services = services;
        this.status = new IdentityStatusText(services);
        this.commands = commands;
    }

    void reload() {
        List<IdentityRow> fresh = new ArrayList<>();
        services.registry().otherUsers().forEach(identity -> fresh.add(new IdentityRow.Member(identity)));
        fresh.add(IdentityRow.Anonymous.INSTANCE);
        rows = List.copyOf(fresh);
        fireTableDataChanged();
    }

    String accessHeading() {
        return "Access vs " + services.registry().primaryUser().name();
    }

    IdentityRow rowAt(int row) {
        return rows.get(row);
    }

    Optional<Integer> rowOf(String identityId) {
        for (int row = 0; row < rows.size(); row++) {
            if (rows.get(row).identity().map(Identity::id).filter(identityId::equals).isPresent()) {
                return Optional.of(row);
            }
        }
        return Optional.empty();
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return column == COMPARE ? Boolean.class : String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == COMPARE && rows.get(row).identity().isPresent();
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        rows.get(row).identity().ifPresent(identity -> commands.setCompared(identity, Boolean.TRUE.equals(value)));
    }

    @Override
    public Object getValueAt(int row, int column) {
        IdentityRow identityRow = rows.get(row);
        return switch (column) {
            case COMPARE -> identityRow.identity().map(Identity::compared).orElse(true);
            case NAME -> identityRow.identity().map(Identity::name).orElse(Principal.ANONYMOUS_NAME);
            case ACCESS -> identityRow.identity().map(identity -> shortRole(identity.role())).orElse(NO_ACCESS_LEVEL);
            case AUTH -> identityRow.identity().map(identity -> AuthLabels.identityKindShort(identity.authKind()))
                    .orElse("None");
            default -> identityRow.identity().isPresent() ? status.of(identityRow) : ALWAYS_INCLUDED;
        };
    }

    static String shortRole(IdentityRole role) {
        return switch (role) {
            case PEER -> "Same (peer)";
            case LOWER -> "Less access";
            case HIGHER -> "More access";
        };
    }
}
