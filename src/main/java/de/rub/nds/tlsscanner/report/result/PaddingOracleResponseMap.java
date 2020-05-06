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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class PaddingOracleResponseMap extends ProbeResult {

    private final static Logger LOGGER = LogManager.getLogger();

    private final List<PaddingOracleCipherSuiteFingerprint> resultList;

    public PaddingOracleResponseMap(List<PaddingOracleCipherSuiteFingerprint> resultList) {
        super(ProbeType.PADDING_ORACLE);
        this.resultList = resultList;
    }

    @Override
    public void mergeData(SiteReport report) {
        TestResult vulnerable = TestResult.UNCERTAIN;
        if (resultList != null && resultList.isEmpty() && vulnerable == null) {
            vulnerable = TestResult.FALSE;
        } else if (resultList == null) {
            vulnerable = TestResult.COULD_NOT_TEST;
        } else {
            vulnerable = TestResult.FALSE;
            for (PaddingOracleCipherSuiteFingerprint fingerprint : resultList) {
                if (fingerprint.getConsideredVulnerable()) {
                    vulnerable = TestResult.TRUE;
                }
            }
        }
        report.setPaddingOracleTestResultList(resultList);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, vulnerable);
    }

    public List<PaddingOracleCipherSuiteFingerprint> getResultList() {
        return resultList;
    }

}
