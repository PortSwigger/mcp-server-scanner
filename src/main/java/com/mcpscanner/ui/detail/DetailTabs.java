package com.mcpscanner.ui.detail;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.Point;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.IntStream;

public final class DetailTabs {

    private static final String RAW = "Raw";
    private static final String TRAILING_COUNT = " \\(\\d+\\)$";

    private final JTabbedPane pane = new JTabbedPane();

    public JTabbedPane component() {
        return pane;
    }

    public void rebuild(Consumer<DetailTabs> contentTabs, RawJsonView raw) {
        rebuildWithoutRaw(contentTabs.andThen(tabs -> tabs.add(RAW, raw)));
    }

    public void rebuildWithoutRaw(Consumer<DetailTabs> contentTabs) {
        String selected = selectedTitle();
        pane.removeAll();
        contentTabs.accept(this);
        reselect(selected);
    }

    public void add(String title, JComponent content) {
        scrollToTop(content);
        pane.addTab(title, holderOf(content));
    }

    public void addWhen(boolean hasContent, String title, JComponent content) {
        if (hasContent) {
            add(title, content);
        }
    }

    public List<String> titles() {
        return IntStream.range(0, pane.getTabCount()).mapToObj(pane::getTitleAt).toList();
    }

    public String selectedTitle() {
        int index = pane.getSelectedIndex();
        return index < 0 ? "" : pane.getTitleAt(index);
    }

    private void reselect(String title) {
        int index = pane.indexOfTab(title);
        if (index < 0) {
            index = indexOfUncounted(uncounted(title));
        }
        if (index >= 0) {
            pane.setSelectedIndex(index);
        }
    }

    private int indexOfUncounted(String title) {
        return IntStream.range(0, pane.getTabCount())
                .filter(index -> uncounted(pane.getTitleAt(index)).equals(title))
                .findFirst()
                .orElse(-1);
    }

    private static String uncounted(String title) {
        return title.replaceFirst(TRAILING_COUNT, "");
    }

    private static void scrollToTop(JComponent content) {
        if (content instanceof JScrollPane scrollPane) {
            scrollPane.getViewport().setViewPosition(new Point());
        }
    }

    private static JPanel holderOf(JComponent content) {
        JPanel holder = new JPanel(new BorderLayout());
        holder.setOpaque(false);
        holder.add(content, BorderLayout.CENTER);
        return holder;
    }
}
