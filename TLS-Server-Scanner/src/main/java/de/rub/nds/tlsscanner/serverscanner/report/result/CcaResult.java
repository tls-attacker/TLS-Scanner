/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.cca.CcaTestResult;
import org.bouncycastle.util.test.Test;

import java.util.List;

public class CcaResult extends ProbeResult {

    private TestResult vulnerable;
    private List<CcaTestResult> resultList;

    public CcaResult(TestResult vulnerable, List<CcaTestResult> resultList) {
        super(ProbeType.CCA);
        this.vulnerable = vulnerable;
        this.resultList = resultList;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.VULNERABLE_TO_CCA_BYPASS, vulnerable);
        report.setCcaTestResultList(resultList);
    }
}
