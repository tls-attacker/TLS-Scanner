/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.afterprobe;

import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.util.ComparableByteArray;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.afterprobe.RandomnessAfterProbe;
import de.rub.nds.tlsscanner.core.constants.RandomType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.core.report.EntropyReport;
import java.util.LinkedList;
import java.util.List;

/**
 * AfterProbe which analyses the random material extracted using the TLS RNG Probe by employing
 * statistical tests defined by NIST SP 800-22. The test results are then passed onto the
 * SiteReport, displaying them at the end of the scan procedure.
 */
public class ClientRandomnessAfterProbe extends RandomnessAfterProbe<ClientReport> {

    @Override
    public void analyze(ClientReport report) {
        ExtractedValueContainer<ComparableByteArray> randomExtractedValueContainer =
                report.getExtractedValueContainer(
                        TrackableValueType.RANDOM, ComparableByteArray.class);
        ExtractedValueContainer<ComparableByteArray> cbcIvExtractedValueContainer =
                report.getExtractedValueContainer(
                        TrackableValueType.CBC_IV, ComparableByteArray.class);
        boolean usesUnixTime = checkForUnixTime(randomExtractedValueContainer);

        List<ComparableByteArray> extractedRandomList =
                filterRandoms(randomExtractedValueContainer.getExtractedValueList(), usesUnixTime);
        List<ComparableByteArray> extractedIvList =
                cbcIvExtractedValueContainer.getExtractedValueList();

        List<EntropyReport> entropyReport = new LinkedList<>();
        if (report.getEntropyReports() != null) {
            entropyReport.addAll(report.getEntropyReports());
        }
        entropyReport.add(createEntropyReport(extractedRandomList, RandomType.RANDOM));
        entropyReport.add(createEntropyReport(extractedIvList, RandomType.CBC_IV));
        report.putResult(TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM, usesUnixTime);
        report.putResult(TlsAnalyzedProperty.ENTROPY_REPORTS, entropyReport);
    }
}
