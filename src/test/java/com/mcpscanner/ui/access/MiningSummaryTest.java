package com.mcpscanner.ui.access;

import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Container;
import java.awt.Rectangle;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class MiningSummaryTest {

    @Test
    void noToolsShowsNoListAndSaysSo() {
        ToolsToCall none = new ToolsToCall(List.of(), List.of());

        assertThat(components(MiningSummary.of(none))).noneMatch(JList.class::isInstance);
        assertThat(MiningSummary.countText(none)).isEqualTo(
                "No tools will be called, only resource reads, resources/list and prompts.");
    }

    @Test
    void theCountNamesHowManyToolsMayWrite() {
        assertThat(MiningSummary.countText(new ToolsToCall(List.of("list", "archive"), List.of("archive"))))
                .isEqualTo("2 tools (1 may write) will be called, besides resource reads, resources/list and prompts:");
        assertThat(MiningSummary.countText(new ToolsToCall(List.of("list"), List.of())))
                .isEqualTo("1 tool will be called, besides resource reads, resources/list and prompts:");
    }

    @Test
    void theLiveServerWarningAppearsOnlyWhenAToolMayWrite() {
        assertThat(texts(MiningSummary.of(new ToolsToCall(List.of("list"), List.of()))))
                .doesNotContain(MiningSummary.LIVE_SERVER_WARNING);
        assertThat(texts(MiningSummary.of(new ToolsToCall(List.of("archive"), List.of("archive")))))
                .contains(MiningSummary.LIVE_SERVER_WARNING);
    }

    @Test
    void theMineFirstLeadIsAlwaysShown() {
        assertThat(texts(MiningSummary.withLead("lead", new ToolsToCall(List.of(), List.of()))))
                .first().isEqualTo("lead");
    }

    @Test
    void packedAtItsPreferredSizeEveryPartWrapsFullyWithoutOverlapping() {
        List<String> names = IntStream.range(0, 14).mapToObj(i -> "tool_" + i).toList();
        ToolsToCall tools = new ToolsToCall(names, List.of("tool_3"));

        assertStackedWithoutOverlap(MiningSummary.withLead(ModalMiningDialogs.MINE_FIRST_BODY, tools), 4);
        assertStackedWithoutOverlap(MiningSummary.of(tools), 3);
    }

    private static void assertStackedWithoutOverlap(JPanel summary, int parts) {
        summary.setSize(summary.getPreferredSize());
        SwingTree.layOut(summary);

        List<Rectangle> stacked = Stream.of(summary.getComponents()).map(Component::getBounds).toList();
        assertThat(stacked).hasSize(2 * parts - 1).allMatch(bounds -> bounds.height > 0);
        for (int i = 1; i < stacked.size(); i++) {
            assertThat(stacked.get(i).y).isGreaterThanOrEqualTo(stacked.get(i - 1).y + stacked.get(i - 1).height);
        }
        assertThat(stacked.get(stacked.size() - 1).getMaxY()).isLessThanOrEqualTo(summary.getHeight());
        components(summary).stream().filter(JTextArea.class::isInstance).map(JTextArea.class::cast)
                .forEach(area -> assertThat(area.getHeight()).as(area.getText())
                        .isGreaterThanOrEqualTo(wrappedHeight(area)));
    }

    private static int wrappedHeight(JTextArea laidOut) {
        JTextArea measure = new JTextArea(laidOut.getText());
        measure.setFont(laidOut.getFont());
        measure.setBorder(laidOut.getBorder());
        measure.setLineWrap(true);
        measure.setWrapStyleWord(true);
        measure.setSize(laidOut.getWidth(), Short.MAX_VALUE);
        return measure.getPreferredSize().height;
    }

    private static List<String> texts(JComponent root) {
        return components(root).stream().filter(JTextArea.class::isInstance)
                .map(area -> ((JTextArea) area).getText()).toList();
    }

    private static List<Component> components(Component root) {
        Stream<Component> children = root instanceof Container container
                ? Stream.of(container.getComponents()).flatMap(child -> components(child).stream()) : Stream.empty();
        return Stream.concat(Stream.of(root), children).toList();
    }
}
