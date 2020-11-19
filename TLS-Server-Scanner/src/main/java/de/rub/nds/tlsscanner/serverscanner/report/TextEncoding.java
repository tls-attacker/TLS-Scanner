/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
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
