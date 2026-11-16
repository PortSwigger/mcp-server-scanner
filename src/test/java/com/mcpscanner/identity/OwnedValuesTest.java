package com.mcpscanner.identity;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OwnedValuesTest {

    private static final MinedSource SOURCE = new MinedSource("tools/call list_documents", "items[0].doc_id");

    @Test
    void enteredValuesKeepTheOrderTheyWereGiven() {
        Map<String, String> entered = new LinkedHashMap<>();
        entered.put("zeta_id", "9");
        entered.put("alpha_id", "1");

        OwnedValues values = OwnedValues.entered(entered);

        assertThat(values.all()).containsExactly(new EnteredValue("zeta_id", "9"), new EnteredValue("alpha_id", "1"));
        assertThat(values.all()).allMatch(EnteredValue.class::isInstance);
    }

    @Test
    void anArgumentCanHoldSeveralValues() {
        OwnedValues values = OwnedValues.of(List.of(mined("doc_id", "d-1", ValueScope.PRIVATE),
                mined("doc_id", "d-2", ValueScope.PRIVATE)));

        assertThat(values.mined()).extracting(MinedValue::value).containsExactly("d-1", "d-2");
        assertThat(values.all()).allMatch(MinedValue.class::isInstance);
    }

    @Test
    void replacingMinedValuesKeepsEnteredOnes() {
        OwnedValues values = OwnedValues.of(List.of(new EnteredValue("doc_id", "typed"),
                mined("doc_id", "old", ValueScope.PRIVATE)));

        OwnedValues replaced = values.withMined(List.of(mined("org_id", "new", ValueScope.SHARED)));

        assertThat(replaced.entered()).containsExactly(new EnteredValue("doc_id", "typed"));
        assertThat(replaced.mined()).containsExactly(mined("org_id", "new", ValueScope.SHARED));
    }

    @Test
    void clearingMinedValuesKeepsEnteredOnes() {
        OwnedValues values = OwnedValues.of(List.of(mined("doc_id", "d-1", ValueScope.PRIVATE),
                new EnteredValue("note_id", "n-1")));

        assertThat(values.withoutMined().all()).containsExactly(new EnteredValue("note_id", "n-1"));
    }

    @Test
    void replacingEnteredValuesKeepsMinedOnes() {
        OwnedValues values = OwnedValues.of(List.of(new EnteredValue("doc_id", "old"),
                mined("doc_id", "d-1", ValueScope.PRIVATE)));

        OwnedValues replaced = values.withEntered(List.of(new EnteredValue("note_id", "n-1")));

        assertThat(replaced.entered()).containsExactly(new EnteredValue("note_id", "n-1"));
        assertThat(replaced.mined()).containsExactly(mined("doc_id", "d-1", ValueScope.PRIVATE));
    }

    @Test
    void ownerArgumentsPreferAnEnteredValueOverAMinedOne() {
        OwnedValues values = OwnedValues.of(List.of(mined("doc_id", "mined", ValueScope.PRIVATE),
                new EnteredValue("doc_id", "typed")));

        assertThat(values.ownerArguments().all()).containsExactly(Map.entry("doc_id", "typed"));
    }

    @Test
    void ownerArgumentsTakeTheFirstPrivateMinedValueOfAnArgument() {
        OwnedValues values = OwnedValues.of(List.of(mined("doc_id", "d-1", ValueScope.PRIVATE),
                mined("doc_id", "d-2", ValueScope.PRIVATE)));

        assertThat(values.ownerArguments().all()).containsExactly(Map.entry("doc_id", "d-1"));
    }

    @Test
    void ownerArgumentsLeaveOutSharedValues() {
        OwnedValues values = OwnedValues.of(List.of(mined("org_id", "acme", ValueScope.SHARED),
                mined("doc_id", "d-1", ValueScope.PRIVATE)));

        assertThat(values.ownerArguments().all()).containsExactly(Map.entry("doc_id", "d-1"));
    }

    @Test
    void ownerArgumentsNeverTakeASharedValueJustBecauseItWasSeenFirst() {
        OwnedValues values = OwnedValues.of(List.of(mined("id", "p-alice", ValueScope.SHARED),
                mined("id", "p-bob", ValueScope.SHARED), mined("status", "draft", ValueScope.SHARED)));

        assertThat(values.ownerArguments().isEmpty()).isTrue();
    }

    @Test
    void ownerArgumentsTakeAValueTheOwnersReplyAttributesToThem() {
        OwnedValues values = OwnedValues.of(List.of(mined("id", "c-bob", ValueScope.SHARED),
                mined("id", "c-alice", ValueScope.ATTRIBUTED)));

        assertThat(values.ownerArguments().all()).containsExactly(Map.entry("id", "c-alice"));
    }

    @Test
    void ownerArgumentsIgnoreSharedValuesOnceAnyPrivateValueExists() {
        OwnedValues values = OwnedValues.of(List.of(mined("org_id", "acme", ValueScope.SHARED),
                mined("doc_id", "d-1", ValueScope.PRIVATE)));

        assertThat(values.ownerArguments().all()).containsExactly(Map.entry("doc_id", "d-1"));
    }

    @Test
    void ownerArgumentsKeepEnteredArgumentsFirst() {
        OwnedValues values = OwnedValues.of(List.of(mined("doc_id", "d-1", ValueScope.PRIVATE),
                new EnteredValue("note_id", "n-1")));

        assertThat(values.ownerArguments().all().keySet()).containsExactly("note_id", "doc_id");
    }

    @Test
    void ownerArgumentsForAToolThatMayWriteCarryOnlyEnteredValues() {
        OwnedValues values = OwnedValues.of(List.of(mined("invoice_id", "inv-1", ValueScope.PRIVATE),
                new EnteredValue("note_id", "n-1")));

        assertThat(values.ownerArguments().forTool(false)).containsExactly(Map.entry("note_id", "n-1"));
        assertThat(values.ownerArguments().forTool(true))
                .containsExactly(Map.entry("note_id", "n-1"), Map.entry("invoice_id", "inv-1"));
    }

    @Test
    void noValuesIsEmpty() {
        assertThat(OwnedValues.NONE.isEmpty()).isTrue();
        assertThat(OwnedValues.NONE.ownerArguments().isEmpty()).isTrue();
        assertThat(OwnedValues.entered(Map.of("a", "1")).isEmpty()).isFalse();
    }

    private static MinedValue mined(String argument, String value, ValueScope scope) {
        return new MinedValue(argument, value, SOURCE, scope);
    }
}
