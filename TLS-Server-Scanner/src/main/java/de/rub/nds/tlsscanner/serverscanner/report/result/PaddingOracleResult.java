/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.leak.info.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;
import java.util.List;
import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class PaddingOracleResult extends ProbeResult {

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<InformationLeakTest<PaddingOracleTestInfo>> resultList;

    private TestResult vulnerable;

    public PaddingOracleResult(List<InformationLeakTest<PaddingOracleTestInfo>> resultList, TestResult result) {
        super(ProbeType.PADDING_ORACLE);
        this.resultList = resultList;
        if (this.resultList != null) {
            vulnerable = TestResult.FALSE;
            for (InformationLeakTest informationLeakTest : resultList) {
                if (informationLeakTest.isSignificantDistinctAnswers()) {
                    vulnerable = TestResult.TRUE;
                    return;
                }
            }
        } else {
            /*Check if it had failed because it could not execute the task, eg: no block ciphers supported*/
            if (result == TestResult.COULD_NOT_TEST)
                vulnerable = TestResult.COULD_NOT_TEST;
            else
                vulnerable = TestResult.ERROR_DURING_TEST;

        }
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setPaddingOracleTestResultList(resultList);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, vulnerable);
    }

    public List<InformationLeakTest<PaddingOracleTestInfo>> getResultList() {
        return resultList;
    }

}
