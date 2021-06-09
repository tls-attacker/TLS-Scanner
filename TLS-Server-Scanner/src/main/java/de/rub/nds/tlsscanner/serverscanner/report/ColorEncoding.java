/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.tlsscanner.serverscanner.constants.AnsiColor;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import java.util.HashMap;

public class ColorEncoding {

    private HashMap<TestResult, AnsiColor> colorMap;

    public ColorEncoding() {
        colorMap = null;
    }

    public ColorEncoding(HashMap<TestResult, AnsiColor> colorMap) {
        this.colorMap = colorMap;
    }

    public AnsiColor getColor(TestResult result) {
        AnsiColor color = colorMap.get(result);
        return color;
    }

    public String encode(TestResult result, String encodedText) {
        AnsiColor color = this.getColor(result);
        if (color != AnsiColor.DEFAULT_COLOR) {
            return color.getCode() + encodedText + AnsiColor.RESET.getCode();
        } else {
            return encodedText;
        }
    }

}
