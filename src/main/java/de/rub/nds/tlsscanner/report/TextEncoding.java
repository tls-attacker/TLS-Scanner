/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsscanner.rating.TestResult;
import java.util.HashMap;

public class TextEncoding {

    private HashMap<TestResult, String> textEncodingMap = null;

    public TextEncoding() {
    }

    public TextEncoding(HashMap<TestResult, String> textEncodingMap) {
        this.textEncodingMap = textEncodingMap;
    }

    public HashMap<TestResult, String> getTextEncodingMap() {
        return textEncodingMap;
    }

    public String encode(TestResult result) {
        return textEncodingMap.get(result);
    }
}
