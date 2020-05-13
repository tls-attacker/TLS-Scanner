/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.leak.InformationLeakTest;
import de.rub.nds.tlsscanner.leak.info.DirectRaccoonOracleTestInfo;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoonResult extends ProbeResult {

    private List<InformationLeakTest<DirectRaccoonOracleTestInfo>> resultList;

    private TestResult vulnerable;

    public DirectRaccoonResult(List<InformationLeakTest<DirectRaccoonOracleTestInfo>> resultList) {
        super(ProbeType.DIRECT_RACCOON);
        this.resultList = resultList;
        if (resultList != null) {
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
        report.putResult(AnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON, vulnerable);
    }

    public List<InformationLeakTest<DirectRaccoonOracleTestInfo>> getResultList() {
        return resultList;
    }
}
