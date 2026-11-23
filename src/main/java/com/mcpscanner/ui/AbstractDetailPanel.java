package com.mcpscanner.ui;

import com.mcpscanner.scan.ScanMode;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.ui.detail.Chip;
import com.mcpscanner.ui.detail.DeclaredTitle;
import com.mcpscanner.ui.detail.DetailSession;
import com.mcpscanner.ui.detail.DetailTabs;
import com.mcpscanner.ui.detail.RawJsonView;
import com.mcpscanner.ui.sendto.SendToBinding;
import com.mcpscanner.ui.widgets.DetailText;
import com.mcpscanner.ui.widgets.Placeholders;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.util.function.Supplier;
import java.util.List;
import java.util.Optional;

abstract class AbstractDetailPanel<T> extends JPanel implements InventoryDetailPanel<T> {

    private static final String CARD_EMPTY = "empty";
    private static final String CARD_DETAIL = "detail";

    private final CardLayout cards = new CardLayout();
    private final DetailSubject<T> subject;
    private final DetailHeader<T> header;
    private final DetailText description = DetailText.prose();
    private final DetailTabs tabs = new DetailTabs();
    private final RawJsonView rawView;
    private DetailSession session = DetailSession.none();
    private T shownItem;

    protected AbstractDetailPanel(DetailSubject<T> subject) {
        this(subject, InventoryTicks.SCAN_SELECTION);
    }

    protected AbstractDetailPanel(DetailSubject<T> subject, InventoryTicks ticks) {
        super();
        this.subject = subject;
        this.header = new DetailHeader<>(subject.noun(), ticks);
        this.rawView = new RawJsonView(subject.rawHint());
        setLayout(cards);
        add(placeholderCard(subject.noun()), CARD_EMPTY);
    }

    protected final void installDetailCard(JComponent... linesBelowHeader) {
        add(DetailCard.of(tabs.component(), headingLines(linesBelowHeader)), CARD_DETAIL);
        cards.show(this, CARD_EMPTY);
    }

    protected abstract void showTabs(T item, DetailTabs tabs);

    protected List<JComponent> headerLine(T item) {
        return List.of();
    }

    protected Optional<String> titleOf(T item) {
        return DeclaredTitle.firstOf(raw(item).path("title"));
    }

    protected final JsonNode raw(T item) {
        return subject.rawOf().apply(item);
    }

    protected final DetailSession session() {
        return session;
    }

    @Override
    public final JComponent component() {
        return this;
    }

    @Override
    public final void show(T item) {
        shownItem = item;
        render(item);
        cards.show(this, CARD_DETAIL);
    }

    @Override
    public final void clear() {
        shownItem = null;
        cards.show(this, CARD_EMPTY);
    }

    @Override
    public final void useSession(DetailSession newSession) {
        if (session.equals(newSession)) {
            return;
        }
        session = newSession;
        if (shownItem != null) {
            render(shownItem);
        }
    }

    @Override
    public final void bindSendTo(SendToBinding<T> binding) {
        header.bindSendTo(binding);
    }

    @Override
    public final void bindScan(ScanItemBinding<T> binding, Supplier<ScanMode> mode) {
        header.bindScan(binding, mode);
    }

    @Override
    public final void refreshActions() {
        header.refresh();
    }

    final DetailHeader<T> header() {
        return header;
    }

    final JLabel headingLabel() {
        return header.heading();
    }

    final JLabel nameBesideTitle() {
        return header.nameBesideTitle();
    }

    final Chip nounChip() {
        return header.nounChip();
    }

    final JLabel problemsLine() {
        return header.problemsLine();
    }

    final JPanel extraHeaderLine() {
        return header.extraLine();
    }

    final DetailTabs tabs() {
        return tabs;
    }

    final RawJsonView rawView() {
        return rawView;
    }

    final DetailText description() {
        return description;
    }

    private void render(T item) {
        header.show(item, String.valueOf(MalformedRows.mark(item, textOrEmpty(subject.nameOf().apply(item)))),
                titleOf(item), headerLine(item));
        description.show(subject.descriptionOf().apply(item));
        rawView.show(raw(item));
        tabs.rebuild(content -> showTabs(item, content), rawView);
    }

    private JComponent[] headingLines(JComponent... linesBelowHeader) {
        JComponent[] lines = new JComponent[linesBelowHeader.length + 1];
        lines[0] = header;
        System.arraycopy(linesBelowHeader, 0, lines, 1, linesBelowHeader.length);
        return lines;
    }

    private static JPanel placeholderCard(String noun) {
        JPanel card = new JPanel(new BorderLayout());
        card.add(Placeholders.centred("Select a " + noun + " to view its details."), BorderLayout.CENTER);
        return card;
    }

    private static String textOrEmpty(String value) {
        return value != null ? value : "";
    }
}
