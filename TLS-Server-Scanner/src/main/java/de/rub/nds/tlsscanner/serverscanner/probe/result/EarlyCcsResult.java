/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class EarlyCcsResult extends ProbeResult<ServerReport> {

    private final EarlyCcsVulnerabilityType earlyCcsVulnerabilityType;

    public EarlyCcsResult(EarlyCcsVulnerabilityType earlyCcsVulnerabilityType) {
        super(TlsProbeType.EARLY_CCS);
        this.earlyCcsVulnerabilityType = earlyCcsVulnerabilityType;
    }

    @Override
    public void mergeData(ServerReport report) {
        if (earlyCcsVulnerabilityType == null) {
            report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, TestResult.COULD_NOT_TEST);
        } else {
            switch (earlyCcsVulnerabilityType) {
                case VULN_EXPLOITABLE:
                case VULN_NOT_EXPLOITABLE:
                    report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, Boolean.TRUE);
                    break;
                case NOT_VULNERABLE:
                    report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, Boolean.FALSE);
                    break;
                case UNKNOWN:
                    report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, TestResult.COULD_NOT_TEST);
            }
        }
    }
}
