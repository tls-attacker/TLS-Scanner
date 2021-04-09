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
import de.rub.nds.tlsscanner.serverscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class MacResult extends ProbeResult {

    private final CheckPattern appDataPattern;
    private final CheckPattern finishedPattern;
    private final CheckPattern verifyPattern;

    public MacResult(CheckPattern appDataPattern, CheckPattern finishedPattern, CheckPattern verifyPattern) {
        super(ProbeType.MAC);
        this.appDataPattern = appDataPattern;
        this.finishedPattern = finishedPattern;
        this.verifyPattern = verifyPattern;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setMacCheckPatternAppData(appDataPattern);
        report.setMacCheckPatternFinished(finishedPattern);
        report.setVerifyCheckPattern(verifyPattern);
    }

}
