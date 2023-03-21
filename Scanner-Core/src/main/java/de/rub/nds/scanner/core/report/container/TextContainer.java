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

public class TextContainer extends ReportContainer {

    private String text;
    private AnsiColor color;

    public TextContainer(String text, AnsiColor color) {
        super(ScannerDetail.NORMAL);
        this.text = text;
        this.color = color;
    }

    public TextContainer(String text, AnsiColor color, ScannerDetail detail) {
        super(detail);
        this.text = text;
        this.color = color;
    }

    @Override
    public void print(StringBuilder builder, int depth, boolean useColor) {
        println(builder, depth, useColor);
        builder.append("\n");
    }

    public void println(StringBuilder builder, int depth, boolean useColor) {
        addDepth(builder, depth);
        addColor(builder, color, text, useColor);
    }

    public String getText() {
        return text;
    }
}
