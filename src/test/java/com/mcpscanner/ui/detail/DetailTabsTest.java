package com.mcpscanner.ui.detail;

import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

import java.awt.Dimension;
import java.awt.Point;

import static org.assertj.core.api.Assertions.assertThat;

class DetailTabsTest {

    private final DetailTabs tabs = new DetailTabs();
    private final RawJsonView raw = new RawJsonView("hint");

    @Test
    void rebuildingShowsAScrollingTabFromTheTop() {
        JScrollPane parameters = scrolledHalfwayDown();

        tabs.rebuild(content -> content.add("Parameters", parameters), raw);

        assertThat(parameters.getViewport().getViewPosition().y).isZero();
    }

    @Test
    void addsOnlyTabsWithContentAndRawLast() {
        tabs.rebuild(content -> {
            content.addWhen(true, "Description", new JLabel("d"));
            content.addWhen(false, "Parameters", new JLabel("p"));
            content.add("Output schema", new JLabel("o"));
        }, raw);

        assertThat(tabs.titles()).containsExactly("Description", "Output schema", "Raw");
    }

    @Test
    void withNoContentTabsOnlyRawIsShown() {
        tabs.rebuild(content -> { }, raw);

        assertThat(tabs.titles()).containsExactly("Raw");
        assertThat(SwingUtilities.isDescendingFrom(raw, tabs.component())).isTrue();
    }

    @Test
    void rebuildingWithoutRawDropsTheRawTab() {
        tabs.rebuild(content -> content.add("Overview", new JLabel("o")), raw);

        tabs.rebuildWithoutRaw(content -> content.add("Overview", new JLabel("o")));

        assertThat(tabs.titles()).containsExactly("Overview");
        assertThat(SwingUtilities.isDescendingFrom(raw, tabs.component())).isFalse();
    }

    @Test
    void rebuildingReplacesThePreviousTabs() {
        tabs.rebuild(content -> content.add("Description", new JLabel("d")), raw);

        tabs.rebuild(content -> content.add("Arguments", new JLabel("a")), raw);

        assertThat(tabs.titles()).containsExactly("Arguments", "Raw");
    }

    @Test
    void keepsTheSelectedTabWhenItIsStillPresent() {
        tabs.rebuild(content -> content.add("Description", new JLabel("d")), raw);
        tabs.component().setSelectedIndex(1);

        tabs.rebuild(content -> content.add("Description", new JLabel("d")), raw);

        assertThat(tabs.selectedTitle()).isEqualTo("Raw");
    }

    @Test
    void keepsACountedTabSelectedWhenOnlyItsCountChanges() {
        tabs.rebuild(content -> {
            content.add("Description", new JLabel("d"));
            content.add("Arguments (3)", new JLabel("a"));
        }, raw);
        tabs.component().setSelectedIndex(1);

        tabs.rebuild(content -> {
            content.add("Description", new JLabel("d"));
            content.add("Arguments (0)", new JLabel("a"));
        }, raw);

        assertThat(tabs.selectedTitle()).isEqualTo("Arguments (0)");
    }

    @Test
    void selectsTheFirstTabWhenTheSelectedOneIsGone() {
        tabs.rebuild(content -> content.add("Parameters", new JLabel("p")), raw);

        tabs.rebuild(content -> content.add("Description", new JLabel("d")), raw);

        assertThat(tabs.selectedTitle()).isEqualTo("Description");
    }

    @Test
    void leavesTheVisibilityOfTabContentAlone() {
        JLabel first = new JLabel("first");
        JLabel second = new JLabel("second");

        tabs.rebuild(content -> {
            content.add("First", first);
            content.add("Second", second);
        }, raw);

        assertThat(first.isVisible()).isTrue();
        assertThat(second.isVisible()).isTrue();
    }

    private static JScrollPane scrolledHalfwayDown() {
        JPanel tall = new JPanel();
        tall.setPreferredSize(new Dimension(100, 1000));
        JScrollPane scrollPane = new JScrollPane(tall);
        scrollPane.setSize(100, 100);
        SwingTree.layOut(scrollPane);
        scrollPane.getViewport().setViewPosition(new Point(0, 500));
        return scrollPane;
    }
}
