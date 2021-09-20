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
import de.rub.nds.tlsscanner.serverscanner.leak.DirectRaccoonOracleTestInfo;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.scanner.core.vectorstatistics.InformationLeakTest;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoonResult extends ProbeResult<SiteReport> {

    private List<InformationLeakTest<DirectRaccoonOracleTestInfo>> resultList;

    private TestResult vulnerable;

    public DirectRaccoonResult(TestResult result) {
        super(TlsProbeType.DIRECT_RACCOON);
        this.vulnerable = result;
        resultList = new LinkedList<>();
    }

    public DirectRaccoonResult(List<InformationLeakTest<DirectRaccoonOracleTestInfo>> resultList) {
        super(TlsProbeType.DIRECT_RACCOON);
        this.resultList = resultList;
        if (this.resultList != null) {
            vulnerable = TestResult.FALSE;
            for (InformationLeakTest<DirectRaccoonOracleTestInfo> informationLeakTest : resultList) {
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
        report.setDirectRaccoonResultList(resultList);
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON, vulnerable);
    }

    public List<InformationLeakTest<DirectRaccoonOracleTestInfo>> getResultList() {
        return resultList;
    }
}
