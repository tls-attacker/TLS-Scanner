/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class MacResult extends ProbeResult<ServerReport> {

    private final CheckPattern appDataPattern;
    private final CheckPattern finishedPattern;
    private final CheckPattern verifyPattern;

    public MacResult(CheckPattern appDataPattern, CheckPattern finishedPattern, CheckPattern verifyPattern) {
        super(TlsProbeType.MAC);
        this.appDataPattern = appDataPattern;
        this.finishedPattern = finishedPattern;
        this.verifyPattern = verifyPattern;
    }

    @Override
    public void mergeData(ServerReport report) {
        report.setMacCheckPatternAppData(appDataPattern);
        report.setMacCheckPatternFinished(finishedPattern);
        report.setVerifyCheckPattern(verifyPattern);
    }

}
