/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.LinkedList;

public class TlsRngResult extends ProbeResult {

    private final LinkedList<ComparableByteArray> extractedIVList;

    private final LinkedList<ComparableByteArray> extractedServerRandomList;

    private final LinkedList<ComparableByteArray> extractedSessionIDList;

    private final boolean usesUnixtime;

    public TlsRngResult(LinkedList<ComparableByteArray> extractedIVList,
        LinkedList<ComparableByteArray> extractedServerRandomList,
        LinkedList<ComparableByteArray> extractedSessionIDList, boolean usesUnixtime) {
        super(ProbeType.RNG);
        this.extractedIVList = extractedIVList;
        this.extractedServerRandomList = extractedServerRandomList;
        this.extractedSessionIDList = extractedSessionIDList;
        this.usesUnixtime = usesUnixtime;
    }

    @Override
    public void mergeData(SiteReport report) {

        // report.putResult(AnalyzedProperty.RNG_EXTRACTED, TestResult.TRUE);

        // Add extracted values to report regardless if the required amount was
        // collected or not.
        // report.setExtractedIVList(extractedIVList);
        // report.setExtractedRandomList(extractedServerRandomList);
        // report.setExtractedSessionIDList(extractedSessionIDList);

        // report.putUnixtimeResult(usesUnixtime);
        report.putResult(AnalyzedProperty.USES_UNIX_TIME_IN_SERVER_RANDOM, usesUnixtime);
    }
}
