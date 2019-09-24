package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsscanner.constants.AnsiColor;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.AnalyzedPropertyCategory;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PrintingScheme {

    private static final Logger LOGGER = LogManager.getLogger();

    private HashMap<AnalyzedProperty, ColorEncoding> colorEncodings;

    private HashMap<AnalyzedPropertyCategory, TextEncoding> textEncodings;

    private TextEncoding defaultTextEncoding;
    private ColorEncoding defaultColorEncoding;

    public PrintingScheme() {
    }

    public PrintingScheme(HashMap<AnalyzedProperty, ColorEncoding> colorEncodings, HashMap<AnalyzedPropertyCategory, TextEncoding> textEncodings, TextEncoding defaultTextEncoding, ColorEncoding defaultColorEncoding) {
        this.colorEncodings = colorEncodings;
        this.textEncodings = textEncodings;
        this.defaultTextEncoding = defaultTextEncoding;
        this.defaultColorEncoding = defaultColorEncoding;
    }

    public HashMap<AnalyzedProperty, ColorEncoding> getColorEncodings() {
        return colorEncodings;
    }

    public HashMap<AnalyzedPropertyCategory, TextEncoding> getTextEncodings() {
        return textEncodings;
    }

    public String getEncodedString(SiteReport report, AnalyzedProperty property) {
        TestResult result = report.getResult(property);
        TextEncoding textEncoding = textEncodings.getOrDefault(property.getCategory(), defaultTextEncoding);
        ColorEncoding colorEncoding = colorEncodings.getOrDefault(result, defaultColorEncoding);
        String encodedText = textEncoding.encode(result);
        return colorEncoding.encode(result, encodedText);
    }

    public static PrintingScheme getDefaultPrintingScheme() {
        HashMap<TestResult, String> textEncodingMap = new HashMap<>();
        textEncodingMap.put(TestResult.COULD_NOT_TEST, "could not test");
        textEncodingMap.put(TestResult.ERROR_DURING_TEST, "error");
        textEncodingMap.put(TestResult.FALSE, "false");
        textEncodingMap.put(TestResult.NOT_TESTED_YET, "not tested yet");
        textEncodingMap.put(TestResult.TIMEOUT, "timeout");
        textEncodingMap.put(TestResult.TRUE, "true");
        textEncodingMap.put(TestResult.UNCERTAIN, "uncertain");
        textEncodingMap.put(TestResult.UNSUPPORTED, "unsupported by tls-scanner");
        TextEncoding defaultTextEncoding = new TextEncoding(textEncodingMap);
        HashMap<TestResult, AnsiColor> ansiColorMap = new HashMap<>();
        ansiColorMap.put(TestResult.COULD_NOT_TEST, AnsiColor.ANSI_BLUE);
        ansiColorMap.put(TestResult.ERROR_DURING_TEST, AnsiColor.ANSI_RED_BACKGROUND);
        ansiColorMap.put(TestResult.FALSE, AnsiColor.DEFAULT_COLOR);
        ansiColorMap.put(TestResult.NOT_TESTED_YET, AnsiColor.ANSI_WHITE);
        ansiColorMap.put(TestResult.TIMEOUT, AnsiColor.ANSI_PURPLE_BACKGROUND);
        ansiColorMap.put(TestResult.TRUE, AnsiColor.DEFAULT_COLOR);
        ansiColorMap.put(TestResult.UNCERTAIN, AnsiColor.ANSI_YELLOW_BACKGROUND);
        ansiColorMap.put(TestResult.UNSUPPORTED, AnsiColor.ANSI_CYAN);
        ColorEncoding defaultColorEncoding = new ColorEncoding(ansiColorMap);

        HashMap<TestResult, String> attackEncodingMap = new HashMap<>();
        attackEncodingMap.put(TestResult.COULD_NOT_TEST, "could not test (not vulnerable)");
        attackEncodingMap.put(TestResult.ERROR_DURING_TEST, "error");
        attackEncodingMap.put(TestResult.FALSE, "not vulnerable");
        attackEncodingMap.put(TestResult.NOT_TESTED_YET, "not tested yet");
        attackEncodingMap.put(TestResult.TIMEOUT, "timeout");
        attackEncodingMap.put(TestResult.TRUE, "vulnerable");
        attackEncodingMap.put(TestResult.UNCERTAIN, "uncertain - requires manual testing");
        attackEncodingMap.put(TestResult.UNSUPPORTED, "unsupported by TLS-Scanner");

        HashMap<TestResult, AnsiColor> redTrueGreenFalseColorMap = new HashMap<>();
        redTrueGreenFalseColorMap.put(TestResult.COULD_NOT_TEST, AnsiColor.ANSI_BLUE);
        redTrueGreenFalseColorMap.put(TestResult.ERROR_DURING_TEST, AnsiColor.ANSI_RED_BACKGROUND);
        redTrueGreenFalseColorMap.put(TestResult.FALSE, AnsiColor.ANSI_GREEN);
        redTrueGreenFalseColorMap.put(TestResult.NOT_TESTED_YET, AnsiColor.ANSI_WHITE);
        redTrueGreenFalseColorMap.put(TestResult.TIMEOUT, AnsiColor.ANSI_PURPLE_BACKGROUND);
        redTrueGreenFalseColorMap.put(TestResult.TRUE, AnsiColor.ANSI_RED);
        redTrueGreenFalseColorMap.put(TestResult.UNCERTAIN, AnsiColor.ANSI_YELLOW_BACKGROUND);
        redTrueGreenFalseColorMap.put(TestResult.UNSUPPORTED, AnsiColor.ANSI_CYAN);

        ColorEncoding attackColorEncoding = new ColorEncoding(redTrueGreenFalseColorMap);
        HashMap<AnalyzedProperty, ColorEncoding> colorMap = new HashMap<>();
        for (AnalyzedProperty prop : AnalyzedProperty.values()) {
            if (prop.getCategory() == AnalyzedPropertyCategory.ATTACKS) {
                colorMap.put(prop, attackColorEncoding);
            }
        }

        HashMap<AnalyzedPropertyCategory, TextEncoding> textMap = new HashMap<>();
        textMap.put(AnalyzedPropertyCategory.ATTACKS, new TextEncoding(attackEncodingMap));
        PrintingScheme scheme = new PrintingScheme(colorMap, textMap, defaultTextEncoding, defaultColorEncoding);
        return scheme;
    }
}
