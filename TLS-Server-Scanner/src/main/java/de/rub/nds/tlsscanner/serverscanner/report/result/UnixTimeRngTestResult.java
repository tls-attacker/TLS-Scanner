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
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class UnixTimeRngTestResult extends ProbeResult {

    private final TestResult usesUnixTime;

    public UnixTimeRngTestResult(TestResult usesUnixTime) {
        super(ProbeType.RNG);
        this.usesUnixTime = usesUnixTime;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.USES_UNIX_TIME_IN_SERVER_RANDOM, usesUnixTime);
    }
}
