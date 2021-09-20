/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.leak.info.BleichenbacherOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;
import java.util.LinkedList;
import java.util.List;

public class BleichenbacherResult extends ProbeResult {

    private final List<InformationLeakTest<BleichenbacherOracleTestInfo>> resultList;

    private TestResult vulnerable;

    public BleichenbacherResult(TestResult result) {
        super(ProbeType.BLEICHENBACHER);
        this.vulnerable = result;
        resultList = new LinkedList<>();
    }

    public BleichenbacherResult(List<InformationLeakTest<BleichenbacherOracleTestInfo>> resultList) {
        super(ProbeType.BLEICHENBACHER);
        this.resultList = resultList;
        if (this.resultList != null) {
            vulnerable = TestResult.FALSE;
            for (InformationLeakTest informationLeakTest : resultList) {
                if (informationLeakTest.isSignificantDistinctAnswers()) {
                    vulnerable = TestResult.TRUE;
                }
            }
        } else {
            vulnerable = TestResult.ERROR_DURING_TEST;
        }
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER, vulnerable);
        report.setBleichenbacherTestResultList(resultList);
    }

}
