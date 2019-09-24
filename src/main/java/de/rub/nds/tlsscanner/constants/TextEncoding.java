package de.rub.nds.tlsscanner.constants;

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
