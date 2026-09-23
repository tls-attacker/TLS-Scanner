/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.SummarizableTestResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.ColorEncoding;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.scanner.core.report.TestResultTextEncoder;
import de.rub.nds.scanner.core.report.markup.SemanticMarkup;
import java.util.List;
import java.util.stream.Collectors;

/** Formats results which list the features a fault has been observed for. */
public class FaultResultFormatter {

    private static final TestResultTextEncoder TEXT_ENCODER =
            new TestResultTextEncoder(DefaultPrintingScheme.getDefaultTextEncodings());

    private static final ColorEncoding COLOR_ENCODING =
            DefaultPrintingScheme.getDefaultColorEncoding(
                    SemanticMarkup.RESULT_BAD, SemanticMarkup.RESULT_GOOD);

    private FaultResultFormatter() {
        // Private constructor to prevent instantiation of utility class
    }

    /**
     * Returns the summarized result of the given property followed by the features the fault has
     * been observed for.
     *
     * @param report the report holding the result
     * @param property the property to format
     * @return the text representation of the result
     */
    public static String getValueText(ScanReport report, AnalyzedProperty property) {
        TestResult result = report.getResult(property);
        String summaryText = TEXT_ENCODER.encode(getSummary(result));
        List<?> faults = getFaults(result);
        if (faults == null || faults.isEmpty()) {
            return summaryText;
        }
        return summaryText
                + " ("
                + faults.stream().map(String::valueOf).collect(Collectors.joining(", "))
                + ")";
    }

    /**
     * Returns the color for the given property, treating a listed fault as a bad result.
     *
     * @param report the report holding the result
     * @param property the property to determine the color for
     * @return the color of the result
     */
    public static SemanticMarkup getValueColor(ScanReport report, AnalyzedProperty property) {
        SemanticMarkup color = COLOR_ENCODING.getColor(getSummary(report.getResult(property)));
        return color == null ? SemanticMarkup.NEUTRAL : color;
    }

    private static TestResults getSummary(TestResult result) {
        if (result instanceof SummarizableTestResult) {
            return ((SummarizableTestResult) result).getSummarizedResult();
        }
        if (result instanceof ListResult) {
            List<?> list = ((ListResult<?>) result).getList();
            return list == null ? TestResults.NOT_TESTED_YET : TestResults.of(!list.isEmpty());
        }
        if (result instanceof TestResults) {
            return (TestResults) result;
        }
        return TestResults.ERROR_DURING_TEST;
    }

    private static List<?> getFaults(TestResult result) {
        return result instanceof ListResult ? ((ListResult<?>) result).getList() : null;
    }
}
