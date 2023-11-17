/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket;

import de.rub.nds.scanner.core.probe.result.SummarizableTestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.core.vector.statistics.TestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.TicketPaddingOracleSecondByteTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.SessionTicketPaddingOracleProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPaddingOracleVectorLast;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPaddingOracleVectorSecond;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketVector;
import java.util.ArrayList;
import java.util.List;

public class TicketPaddingOracleResult implements SummarizableTestResult {
    private final TestResults overallResult;

    private final List<TicketPaddingOracleOffsetResult> positionResults;

    private final List<TicketPaddingOracleVectorLast> lastVectorsWithRareResponses;
    private final List<TicketPaddingOracleVectorSecond> secondVectorsWithRareResponses;

    public TicketPaddingOracleResult(List<TicketPaddingOracleOffsetResult> positionResults) {
        this.positionResults = positionResults;

        boolean last = false;
        boolean second = false;
        lastVectorsWithRareResponses = new ArrayList<>();
        secondVectorsWithRareResponses = new ArrayList<>();

        for (TicketPaddingOracleOffsetResult result : positionResults) {
            if (result.getLastByteLeakTest().isSignificantDistinctAnswers()) {
                last = true;
                lastVectorsWithRareResponses.addAll(
                        getVectorsWithRareResponses(
                                result.getLastByteLeakTest(),
                                TicketPaddingOracleVectorLast.class,
                                2));
                for (InformationLeakTest<TicketPaddingOracleSecondByteTestInfo> leakTest :
                        result.getSecondByteLeakTests()) {
                    if (leakTest.isSignificantDistinctAnswers()) {
                        second = true;
                        secondVectorsWithRareResponses.addAll(
                                getVectorsWithRareResponses(
                                        leakTest, TicketPaddingOracleVectorSecond.class, 1));
                    }
                }
            }
        }

        if (second) {
            overallResult = TestResults.TRUE;
        } else if (last) {
            overallResult = TestResults.PARTIALLY;
        } else {
            overallResult = TestResults.FALSE;
        }
    }

    public TicketPaddingOracleResult(TestResults overallResult) {
        this.overallResult = overallResult;
        this.positionResults = null;
        this.lastVectorsWithRareResponses = null;
        this.secondVectorsWithRareResponses = null;
    }

    private <V extends TicketVector, T extends TestInfo> List<V> getVectorsWithRareResponses(
            InformationLeakTest<T> leakTest, Class<V> vectorClass, int maxOccurences) {
        List<V> ret = new ArrayList<>();
        for (VectorResponse response :
                SessionTicketPaddingOracleProbe.getRareResponses(leakTest, maxOccurences)) {
            ret.add(vectorClass.cast(response.getVector()));
        }
        return ret;
    }

    public TestResults getOverallResult() {
        return this.overallResult;
    }

    public List<TicketPaddingOracleOffsetResult> getPositionResults() {
        return this.positionResults;
    }

    public List<TicketPaddingOracleVectorLast> getLastVectorsWithRareResponses() {
        return this.lastVectorsWithRareResponses;
    }

    public List<TicketPaddingOracleVectorSecond> getSecondVectorsWithRareResponses() {
        return this.secondVectorsWithRareResponses;
    }

    @Override
    public TestResults getSummarizedResult() {
        return overallResult;
    }

    @Override
    public boolean isExplicitSummary() {
        return true;
    }
}
