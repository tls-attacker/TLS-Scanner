/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report;

import de.rub.nds.scanner.core.constants.TestResult;
import java.util.HashMap;

public class TestResultTextEncoder extends Encoder<TestResult> {

    private HashMap<TestResult, String> textEncodingMap = null;

    public TestResultTextEncoder() {
    }

    public TestResultTextEncoder(HashMap<TestResult, String> textEncodingMap) {
        this.textEncodingMap = textEncodingMap;
    }

    public HashMap<TestResult, String> getTextEncodingMap() {
        return textEncodingMap;
    }

    @Override
    public String encode(TestResult result) {
        if (textEncodingMap == null) {
            return result.name();
        }
        String string = textEncodingMap.get(result);
        if (string == null) {
            return result.name();
        } else {
            return string;
        }
    }
}
