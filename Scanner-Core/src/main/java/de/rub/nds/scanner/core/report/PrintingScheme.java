/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.report.ColorEncoding;
import de.rub.nds.scanner.core.constants.AnalyzedPropertyCategory;
import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PrintingScheme {

    private static final Logger LOGGER = LogManager.getLogger();

    private HashMap<AnalyzedProperty, ColorEncoding> colorEncodings;

    private HashMap<AnalyzedPropertyCategory, TextEncoding> textEncodings;

    private HashMap<AnalyzedProperty, TextEncoding> specialTextEncoding;

    private TextEncoding defaultTextEncoding;
    private ColorEncoding defaultColorEncoding;
    private boolean useColors;

    public PrintingScheme() {
    }

    public PrintingScheme(HashMap<AnalyzedProperty, ColorEncoding> colorEncodings,
        HashMap<AnalyzedPropertyCategory, TextEncoding> textEncodings, TextEncoding defaultTextEncoding,
        ColorEncoding defaultColorEncoding, HashMap<AnalyzedProperty, TextEncoding> specialTextEncoding,
        boolean useColors) {
        this.colorEncodings = colorEncodings;
        this.textEncodings = textEncodings;
        this.defaultTextEncoding = defaultTextEncoding;
        this.defaultColorEncoding = defaultColorEncoding;
        this.useColors = useColors;
        this.specialTextEncoding = specialTextEncoding;
    }

    public HashMap<AnalyzedProperty, ColorEncoding> getColorEncodings() {
        return colorEncodings;
    }

    public HashMap<AnalyzedPropertyCategory, TextEncoding> getTextEncodings() {
        return textEncodings;
    }

    public String getEncodedString(ScanReport report, AnalyzedProperty property) {
        TestResult result = report.getResult(property);
        TextEncoding textEncoding = specialTextEncoding.get(property);
        if (textEncoding == null) {
            textEncoding = textEncodings.getOrDefault(property.getCategory(), defaultTextEncoding);
        }
        ColorEncoding colorEncoding = colorEncodings.getOrDefault(property, defaultColorEncoding);
        String encodedText = textEncoding.encode(result);
        if (useColors) {
            return colorEncoding.encode(result, encodedText);
        } else {
            return encodedText;
        }
    }

}
