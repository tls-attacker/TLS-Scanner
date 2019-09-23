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
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class PaddingOracleResponseMap extends ProbeResult {

    private final List<PaddingOracleCipherSuiteFingerprint> resultList;
    private final List<PaddingOracleCipherSuiteFingerprint> shakyEvalList;

    private TestResult vulnerable;

    public PaddingOracleResponseMap(List<PaddingOracleCipherSuiteFingerprint> resultList, List<PaddingOracleCipherSuiteFingerprint> shakyEvalList, TestResult vulnerable) {
        super(ProbeType.PADDING_ORACLE);
        this.resultList = resultList;
        this.shakyEvalList = shakyEvalList;
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (resultList != null && resultList.isEmpty() && vulnerable == null) {
            vulnerable = TestResult.FALSE;
        }
        if(resultList == null)
        {
            vulnerable = TestResult.COULD_NOT_TEST;
        }
        report.setPaddingOracleTestResultList(resultList);
        report.setPaddingOracleShakyEvalResultList(shakyEvalList);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, vulnerable);
    }

    public List<PaddingOracleCipherSuiteFingerprint> getResultList() {
        return resultList;
    }

}
