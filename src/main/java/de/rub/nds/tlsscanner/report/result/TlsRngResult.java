/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.CommonBugProbe;
import de.rub.nds.tlsscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;

import java.util.List;

public class TlsRngResult extends ProbeResult {

    private boolean rng_extracted = false;

    private final List<ComparableByteArray> extractedIVList;

    private final List<ComparableByteArray> extractedServerRandomList;

    private final List<ComparableByteArray> extractedSessionIDList;

    public TlsRngResult(boolean rng_extracted, List<ComparableByteArray> extractedIVList,
            List<ComparableByteArray> extractedServerRandomList, List<ComparableByteArray> extractedSessionIDList) {
        super(ProbeType.RNG);
        this.rng_extracted = rng_extracted;
        this.extractedIVList = extractedIVList;
        this.extractedServerRandomList = extractedServerRandomList;
        this.extractedSessionIDList = extractedSessionIDList;
    }

    @Override
    public void mergeData(SiteReport report) {

        if (rng_extracted) {
            report.putResult(AnalyzedProperty.RNG_EXTRACTED, TestResult.TRUE);
        } else {
            report.putResult(AnalyzedProperty.RNG_EXTRACTED, TestResult.FALSE);
        }

        // Add extracted values to report regardless if the required amount was
        // collected or not.
        report.setExtractedIVList(extractedIVList);
        report.setExtractedRandomList(extractedServerRandomList);
        report.setExtractedSessionIDList(extractedSessionIDList);

    }
}
