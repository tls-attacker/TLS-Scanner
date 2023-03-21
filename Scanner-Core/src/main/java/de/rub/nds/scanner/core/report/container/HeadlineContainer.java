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
import de.rub.nds.scanner.core.report.AnsiColor;

public class HeadlineContainer extends ReportContainer {

    private static int NUMBER_OF_DASHES_IN_H_LINE = 50;

    private final String headline;

    public HeadlineContainer(String headline) {
        super(ScannerDetail.NORMAL);
        this.headline = headline;
    }

    public HeadlineContainer(String headline, ScannerDetail detail) {
        super(detail);
        this.headline = headline;
    }

    @Override
    public void print(StringBuilder builder, int depth, boolean useColor) {
        if (useColor) {
            builder.append(AnsiColor.BOLD.getCode());
            builder.append(getColorByDepth(depth).getCode());
        }
        if (depth == 0) {
            addHLine(builder);
        }
        addHeadlineDepth(builder, depth);
        builder.append(headline);
        if (useColor) {
            builder.append(AnsiColor.RESET.getCode());
        }
        builder.append("\n");
        builder.append("\n");
    }

    private AnsiColor getColorByDepth(int depth) {
        switch (depth) {
            case 0:
                return AnsiColor.PURPLE;
            case 1:
                return AnsiColor.BLUE;
            case 2:
                return AnsiColor.CYAN;
            case 3:
                return AnsiColor.WHITE;
            default:
                return AnsiColor.YELLOW;
        }
    }

    public String getHeadline() {
        return headline;
    }

    private void addHLine(StringBuilder builder) {
        for (int i = 0; i < NUMBER_OF_DASHES_IN_H_LINE; i++) {
            builder.append("-");
        }
        builder.append("\n");
    }
}
