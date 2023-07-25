/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.report.container;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class TableContainer extends ReportContainer {

    private List<TextContainer> headlineList;

    private List<List<TextContainer>> containerTable;

    private int depthIncrease;

    public TableContainer() {
        super(ScannerDetail.NORMAL);
        this.depthIncrease = 0;
        this.containerTable = new LinkedList<>();
    }

    public TableContainer(ScannerDetail detail) {
        super(detail);
        this.depthIncrease = 0;
        this.containerTable = new LinkedList<>();
    }

    public TableContainer(int depthIncrease) {
        super(ScannerDetail.NORMAL);
        this.depthIncrease = depthIncrease;
        this.containerTable = new LinkedList<>();
    }

    public TableContainer(ScannerDetail detail, int depthIncrease) {
        super(detail);
        this.depthIncrease = depthIncrease;
        this.containerTable = new LinkedList<>();
    }

    @Override
    public void print(StringBuilder builder, int depth, boolean useColor) {
        println(builder, depth, useColor);
        builder.append("\n");
    }

    public void println(StringBuilder builder, int depth, boolean useColor) {
        List<Integer> paddings = getColumnPaddings();
        printTableLine(headlineList, paddings, builder, depth, useColor);
        printStripline(paddings, builder, depth);
        for (List<TextContainer> containerLine : containerTable) {
            printTableLine(containerLine, paddings, builder, depth, useColor);
        }
    }

    /**
     * Calculates the padding for each column of the table. Needed to properly align table entries.
     *
     * @return padding A list containing the paddings for each column.
     */
    private List<Integer> getColumnPaddings() {
        List<Integer> paddings = new ArrayList<>(headlineList.size());
        for (int i = 0; i < headlineList.size(); i++) {
            paddings.add(i, headlineList.get(i).getText().length());
        }
        for (List<TextContainer> line : containerTable) {
            for (int i = 0; i < line.size(); i++) {
                paddings.set(i, Math.max(paddings.get(i), line.get(i).getText().length()));
            }
        }
        return paddings;
    }

    private void pad(StringBuilder builder, int n) {
        builder.append(" ".repeat(Math.max(0, n)));
    }

    private void printTableLine(
            List<TextContainer> line,
            List<Integer> paddings,
            StringBuilder builder,
            int depth,
            boolean useColor) {
        addDepth(builder, depth);
        for (int i = 0; i < line.size(); i++) {
            TextContainer container = line.get(i);
            int paddingSpaces = paddings.get(i) - container.getText().length();
            pad(builder, paddingSpaces);
            container.println(builder, 0, useColor);
            builder.append(" | ");
        }
        builder.append("\n");
    }

    private void printStripline(List<Integer> paddings, StringBuilder builder, int depth) {
        addDepth(builder, depth);
        for (Integer padding : paddings) {
            builder.append("-".repeat(padding));
            builder.append(" | ");
        }
        builder.append("\n");
    }

    public void addLineToTable(List<TextContainer> line) {
        this.containerTable.add(line);
    }

    public List<TextContainer> getHeadlineList() {
        return headlineList;
    }

    public void setHeadlineList(List<TextContainer> headlineList) {
        this.headlineList = headlineList;
    }

    public List<List<TextContainer>> getContainerTable() {
        return containerTable;
    }

    public void setContainerTable(List<List<TextContainer>> containerTable) {
        this.containerTable = containerTable;
    }

    public int getDepthIncrease() {
        return depthIncrease;
    }

    public void setDepthIncrease(int depthIncrease) {
        this.depthIncrease = depthIncrease;
    }
}
