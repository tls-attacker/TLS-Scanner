/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.report;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.report.container.KeyValueContainer;
import de.rub.nds.scanner.core.report.container.ReportContainer;
import de.rub.nds.scanner.core.report.container.TextContainer;

public class ReportCreator {

    protected PrintingScheme printingScheme;
    protected ScannerDetail detail;

    public ReportCreator(ScannerDetail detail, PrintingScheme scheme) {
        this.printingScheme = scheme;
        this.detail = detail;
    }

    protected ReportContainer createKeyValueContainer(
            AnalyzedProperty property, ScanReport report) {
        String key = printingScheme.getEncodedKeyText(report, property);
        String value = printingScheme.getEncodedValueText(report, property);
        AnsiColor keyColour = printingScheme.getKeyColor(report, property);
        AnsiColor valueColour = printingScheme.getValueColor(report, property);
        return new KeyValueContainer(key, keyColour, value, valueColour);
    }

    protected ReportContainer createDefaultKeyValueContainer(String key, String value) {
        return new KeyValueContainer(key, AnsiColor.DEFAULT_COLOR, value, AnsiColor.DEFAULT_COLOR);
    }

    protected TextContainer createDefaultTextContainer(String text) {
        return new TextContainer(text, AnsiColor.DEFAULT_COLOR);
    }
}
