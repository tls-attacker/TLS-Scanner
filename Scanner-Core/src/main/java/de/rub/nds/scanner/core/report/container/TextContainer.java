/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report.container;

import de.rub.nds.scanner.core.report.AnsiColor;

public class TextContainer extends ReportContainer {

    private String text;
    private AnsiColor color;

    public TextContainer(String text, AnsiColor color) {
        this.text = text;
        this.color = color;
    }

    @Override
    public void print(StringBuilder builder, int depth, boolean useColor) {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
                                                                       // Tools | Templates.
    }
}
