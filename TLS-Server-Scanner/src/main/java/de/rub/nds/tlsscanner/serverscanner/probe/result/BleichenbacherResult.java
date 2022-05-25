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
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.leak.BleichenbacherOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.LinkedList;
import java.util.List;

public class BleichenbacherResult extends ProbeResult<ServerReport> {

    private final List<InformationLeakTest<BleichenbacherOracleTestInfo>> resultList;

    private TestResult vulnerable;

    public BleichenbacherResult(TestResult result) {
        super(TlsProbeType.BLEICHENBACHER);
        this.vulnerable = result;
        resultList = new LinkedList<>();
    }

    public BleichenbacherResult(List<InformationLeakTest<BleichenbacherOracleTestInfo>> resultList) {
        super(TlsProbeType.BLEICHENBACHER);
        this.resultList = resultList;
        if (this.resultList != null) {
            vulnerable = TestResults.FALSE;
            for (InformationLeakTest informationLeakTest : resultList) {
                if (informationLeakTest.isSignificantDistinctAnswers()) {
                    vulnerable = TestResults.TRUE;
                }
            }
        } else {
            vulnerable = TestResults.ERROR_DURING_TEST;
        }
    }

    @Override
    public void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER, vulnerable);
        report.setBleichenbacherTestResultList(resultList);
    }

}
