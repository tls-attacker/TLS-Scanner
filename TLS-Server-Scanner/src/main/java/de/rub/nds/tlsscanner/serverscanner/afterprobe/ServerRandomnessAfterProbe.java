/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.util.ComparableByteArray;
import de.rub.nds.tlsscanner.core.afterprobe.RandomnessAfterProbe;
import de.rub.nds.tlsscanner.core.constants.RandomType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.core.report.EntropyReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.List;

/**
 * AfterProbe which analyses the random material extracted using the TLS RNG Probe by employing statistical tests
 * defined by NIST SP 800-22. The test results are then passed onto the SiteReport, displaying them at the end of the
 * scan procedure.
 */
public class ServerRandomnessAfterProbe extends RandomnessAfterProbe<ServerReport> {

    @Override
    public void analyze(ServerReport report) {
        ExtractedValueContainer<ComparableByteArray> cookieExtractedValueContainer =
            report.getExtractedValueContainerMap().get(TrackableValueType.COOKIE);
        ExtractedValueContainer<ComparableByteArray> randomExtractedValueContainer =
            report.getExtractedValueContainerMap().get(TrackableValueType.RANDOM);
        ExtractedValueContainer<ComparableByteArray> sessionIdExtractedValueContainer =
            report.getExtractedValueContainerMap().get(TrackableValueType.SESSION_ID);
        ExtractedValueContainer<ComparableByteArray> cbcIvExtractedValueContainer =
            report.getExtractedValueContainerMap().get(TrackableValueType.CBC_IV);
        boolean usesUnixTime = checkForUnixTime(randomExtractedValueContainer);

        List<ComparableByteArray> extractedCookieList = cookieExtractedValueContainer.getExtractedValueList();
        List<ComparableByteArray> extractedRandomList =
            filterRandoms(randomExtractedValueContainer.getExtractedValueList(), usesUnixTime);
        List<ComparableByteArray> extractedIvList = cbcIvExtractedValueContainer.getExtractedValueList();
        List<ComparableByteArray> extractedSessionIdList = sessionIdExtractedValueContainer.getExtractedValueList();

        List<EntropyReport> entropyReport = report.getEntropyReports();
        entropyReport.add(createEntropyReport(extractedRandomList, RandomType.RANDOM));
        entropyReport.add(createEntropyReport(extractedSessionIdList, RandomType.SESSION_ID));
        entropyReport.add(createEntropyReport(extractedCookieList, RandomType.COOKIE));
        entropyReport.add(createEntropyReport(extractedIvList, RandomType.CBC_IV));
        report.putResult(TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM, usesUnixTime);
    }
}
