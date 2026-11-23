package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.IdentityAuthKind;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;

final class AuthKindChoices {

    private final JComboBox<IdentityAuthKind> combo;
    private final GrantCredentialForms grantForms;

    AuthKindChoices(JComboBox<IdentityAuthKind> combo, GrantCredentialForms grantForms) {
        this.combo = combo;
        this.grantForms = grantForms;
    }

    void offer(EditorRole role, IdentityAuthKind selected) {
        List<IdentityAuthKind> offered = offeredTo(role).stream()
                .filter(kind -> kind == selected || grantForms.offers(kind))
                .toList();
        if (!offered.equals(current())) {
            combo.setModel(new DefaultComboBoxModel<>(offered.toArray(IdentityAuthKind[]::new)));
        }
        combo.setSelectedItem(selected);
    }

    List<String> labels() {
        return current().stream().map(AuthLabels::identityKind).toList();
    }

    static List<IdentityAuthKind> offeredTo(EditorRole role) {
        return Arrays.stream(IdentityAuthKind.values())
                .filter(kind -> role.editsPrimary() || kind.offeredToComparedUsers())
                .toList();
    }

    private List<IdentityAuthKind> current() {
        return IntStream.range(0, combo.getItemCount()).mapToObj(combo::getItemAt).toList();
    }
}
