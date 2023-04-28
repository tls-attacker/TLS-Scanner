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

import java.util.LinkedList;
import java.util.List;

public class ListContainer extends ReportContainer {

    private List<ReportContainer> reportContainerList;

    private int depthIncrease;

    public ListContainer() {
        super(ScannerDetail.NORMAL);
        this.reportContainerList = new LinkedList<>();
        this.depthIncrease = 0;
    }

    public ListContainer(int depthIncrease) {
        super(ScannerDetail.NORMAL);
        this.reportContainerList = new LinkedList<>();
        this.depthIncrease = depthIncrease;
    }

    public ListContainer(List<ReportContainer> reportContainerList, int depthIncrease) {
        super(ScannerDetail.NORMAL);
        this.reportContainerList = reportContainerList;
        this.depthIncrease = depthIncrease;
    }

    public ListContainer(List<ReportContainer> reportContainerList) {
        super(ScannerDetail.NORMAL);
        this.reportContainerList = reportContainerList;
        this.depthIncrease = 0;
    }

    @Override
    public void print(StringBuilder builder, int depth, boolean useColor) {
        reportContainerList.forEach(
                container -> {
                    container.print(builder, depth + depthIncrease, useColor);
                });
    }

    public ListContainer add(ReportContainer container) {
        this.reportContainerList.add(container);
        return this;
    }
}
