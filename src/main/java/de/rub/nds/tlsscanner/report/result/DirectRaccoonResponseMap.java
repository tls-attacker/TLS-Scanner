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
import de.rub.nds.tlsscanner.probe.directRaccoon.DirectRaccoonCipherSuiteFingerprint;
import java.util.List;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoonResponseMap extends ProbeResult {

    private List<DirectRaccoonCipherSuiteFingerprint> resultList;

    private TestResult vulnerable;

    public DirectRaccoonResponseMap(List<DirectRaccoonCipherSuiteFingerprint> resultList, TestResult vulnerable) {
        super(ProbeType.DIRECT_RACCOON);
        this.resultList = resultList;
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (resultList != null && resultList.isEmpty() && vulnerable == null) {
            vulnerable = TestResult.FALSE;
        }
        if (resultList == null) {
            vulnerable = TestResult.COULD_NOT_TEST;
        }
        report.setDirectRaccoonResultList(resultList);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON, vulnerable);
    }

    public List<DirectRaccoonCipherSuiteFingerprint> getResultList() {
        return resultList;
    }
}
