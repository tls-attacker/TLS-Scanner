/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report;

import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResult;
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
        if (color != null && color != AnsiColor.DEFAULT_COLOR) {
            return color.getCode() + encodedText + AnsiColor.RESET.getCode();
        } else {
            return encodedText;
        }
    }

}
