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
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.probe.result.bleichenbacher.BleichenbacherTestResult;
import java.util.List;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class BleichenbacherResult extends ProbeResult<ServerReport> {

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
    public void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER, vulnerable);
        report.setBleichenbacherTestResultList(resultList);
    }

}
