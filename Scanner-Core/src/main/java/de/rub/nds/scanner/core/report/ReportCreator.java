/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.report.container.KeyValueContainer;
import de.rub.nds.scanner.core.report.container.ReportContainer;

public class ReportCreator {

    protected PrintingScheme printingScheme;

    public ReportCreator(PrintingScheme scheme) {
        this.printingScheme = scheme;
    }

    protected ReportContainer createKeyValueContainer(AnalyzedProperty property, ScanReport report) {
        String key = printingScheme.getEncodedKeyText(report, property);
        String value = printingScheme.getEncodedValueText(report, property);
        AnsiColor keyColour = printingScheme.getKeyColor(report, property);
        AnsiColor valueColour = printingScheme.getValueColor(report, property);
        return new KeyValueContainer(key, keyColour, value, valueColour);
    }
}
