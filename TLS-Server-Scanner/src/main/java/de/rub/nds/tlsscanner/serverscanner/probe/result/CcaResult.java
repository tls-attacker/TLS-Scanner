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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.cca.CcaTestResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.List;

public class CcaResult extends ProbeResult<ServerReport> {

    private final TestResult vulnerable;
    private final List<CcaTestResult> resultList;

    public CcaResult(TestResult vulnerable, List<CcaTestResult> resultList) {
        super(TlsProbeType.CCA);
        this.vulnerable = vulnerable;
        this.resultList = resultList;
    }

    @Override
    public void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_CCA_BYPASS, vulnerable);
        report.setCcaTestResultList(resultList);
    }
}
