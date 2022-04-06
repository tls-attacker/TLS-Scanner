/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report.container;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.report.AnsiColor;

public abstract class ReportContainer {

    private ScannerDetail detail;

    public ReportContainer(ScannerDetail detail) {
        this.detail = detail;
    }

    public abstract void print(StringBuilder builder, int depth, boolean useColor);

    protected StringBuilder addDepth(StringBuilder builder, int depth) {
        for (int i = 0; i < depth; i++) {
            builder.append("  ");
        }
        return builder;
    }

    protected StringBuilder addHeadlineDepth(StringBuilder builder, int depth) {
        for (int i = 0; i < depth; i++) {
            builder.append("--");
        }
        if (depth > 0) {
            builder.append("|");
        }
        return builder;
    }

    protected StringBuilder addColor(StringBuilder builder, AnsiColor color, String text, boolean useColor) {
        if (useColor) {
            builder.append(color.getCode()).append(text).append(AnsiColor.RESET.getCode());
        } else {
            builder.append(text);
        }
        return builder;
    }

    public ScannerDetail getDetail() {
        return detail;
    }

}
