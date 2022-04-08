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
import de.rub.nds.scanner.core.constants.AnalyzedPropertyCategory;
import de.rub.nds.scanner.core.constants.TestResult;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PrintingScheme {

    private static final Logger LOGGER = LogManager.getLogger();

    private HashMap<AnalyzedProperty, ColorEncoding> valueColorEncodings;

    private HashMap<AnalyzedPropertyCategory, TestResultTextEncoder> valueTextEncodings;

    private HashMap<AnalyzedProperty, TestResultTextEncoder> specialValueTextEncoding;

    private HashMap<AnalyzedProperty, Encoder> keyTextEncoding;

    private TestResultTextEncoder defaultTextEncoding;
    private ColorEncoding defaultColorEncoding;

    public PrintingScheme() {
    }

    public PrintingScheme(HashMap<AnalyzedProperty, ColorEncoding> colorEncodings,
        HashMap<AnalyzedPropertyCategory, TestResultTextEncoder> textEncodings,
        TestResultTextEncoder defaultTextEncoding, ColorEncoding defaultColorEncoding,
        HashMap<AnalyzedProperty, TestResultTextEncoder> specialTextEncoding,
        HashMap<AnalyzedProperty, Encoder> keyTextEncoding) {
        this.valueColorEncodings = colorEncodings;
        this.valueTextEncodings = textEncodings;
        this.defaultTextEncoding = defaultTextEncoding;
        this.defaultColorEncoding = defaultColorEncoding;
        this.specialValueTextEncoding = specialTextEncoding;
        this.keyTextEncoding = keyTextEncoding;
    }

    public HashMap<AnalyzedProperty, ColorEncoding> getValueColorEncodings() {
        return valueColorEncodings;
    }

    public HashMap<AnalyzedPropertyCategory, TestResultTextEncoder> getValueTextEncodings() {
        return valueTextEncodings;
    }

    public String getEncodedString(ScanReport report, AnalyzedProperty property, boolean useColors) {
        TestResult result = report.getResult(property);
        TestResultTextEncoder textEncoding = specialValueTextEncoding.get(property);
        if (textEncoding == null) {
            textEncoding = valueTextEncodings.getOrDefault(property.getCategory(), defaultTextEncoding);
        }
        ColorEncoding colorEncoding = valueColorEncodings.getOrDefault(property, defaultColorEncoding);
        String encodedText = textEncoding.encode(result);
        if (useColors) {
            return colorEncoding.encode(result, encodedText);
        } else {
            return encodedText;
        }
    }

    public String getEncodedValueText(ScanReport report, AnalyzedProperty property) {
        TestResult result = report.getResult(property);
        TestResultTextEncoder textEncoding = specialValueTextEncoding.get(property);
        if (textEncoding == null) {
            textEncoding = valueTextEncodings.getOrDefault(property.getCategory(), defaultTextEncoding);
        }
        return textEncoding.encode(result);
    }

    public String getEncodedKeyText(ScanReport report, AnalyzedProperty property) {
        Encoder textEncoding = keyTextEncoding.getOrDefault(property, new AnalyzedPropertyTextEncoder(null));

        return textEncoding.encode(property);
    }

    public AnsiColor getValueColor(ScanReport report, AnalyzedProperty property) {
        TestResult result = report.getResult(property);
        ColorEncoding colorEncoding = valueColorEncodings.getOrDefault(property, defaultColorEncoding);
        return colorEncoding.getColor(result);
    }

    public AnsiColor getKeyColor(ScanReport report, AnalyzedProperty property) {
        return AnsiColor.DEFAULT_COLOR;
    }

}
