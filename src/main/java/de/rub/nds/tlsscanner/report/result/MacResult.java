/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.report.SiteReport;

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
        report.setMacCheckPatterAppData(appDataPattern);
        report.setMacCheckPatternFinished(finishedPattern);
        report.setVerifyCheckPattern(verifyPattern);
    }

}
