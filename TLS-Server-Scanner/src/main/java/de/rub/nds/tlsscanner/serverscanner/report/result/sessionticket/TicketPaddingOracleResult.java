/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket;

import java.util.ArrayList;
import java.util.List;

import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.leak.info.TestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.info.TicketPoSecondByteTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.SessionTicketPaddingOracleProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPoVectorLast;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPoVectorSecond;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketVector;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionDependentResult;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;

public class TicketPaddingOracleResult extends VersionDependentResult {
    private final TestResult overallResult;

    private final List<TicketPaddingOracleOffsetResult> positionResults;

    private final List<TicketPoVectorLast> lastVectorsWithRareResponses;
    private final List<TicketPoVectorSecond> secondVectorsWithRareResponses;

    public TicketPaddingOracleResult(ProtocolVersion protocolVersion,
        List<TicketPaddingOracleOffsetResult> positionResults) {
        super(protocolVersion);
        this.positionResults = positionResults;

        boolean last = false;
        boolean second = false;
        lastVectorsWithRareResponses = new ArrayList<>();
        secondVectorsWithRareResponses = new ArrayList<>();

        for (TicketPaddingOracleOffsetResult result : positionResults) {
            if (result.getLastByteLeakTest().isSignificantDistinctAnswers()) {
                last = true;
                lastVectorsWithRareResponses
                    .addAll(getVectorsWithRareResponses(result.getLastByteLeakTest(), TicketPoVectorLast.class, 2));
                for (InformationLeakTest<TicketPoSecondByteTestInfo> leakTest : result.getSecondByteLeakTests()) {
                    if (leakTest.isSignificantDistinctAnswers()) {
                        second = true;
                        secondVectorsWithRareResponses
                            .addAll(getVectorsWithRareResponses(leakTest, TicketPoVectorSecond.class, 1));
                    }
                }
            }
        }

        if (second) {
            overallResult = TestResult.TRUE;
        } else if (last) {
            overallResult = TestResult.PARTIALLY;
        } else {
            overallResult = TestResult.FALSE;
        }
    }

    public TicketPaddingOracleResult(ProtocolVersion protocolVersion, TestResult overallResult) {
        super(protocolVersion);
        this.overallResult = overallResult;
        this.positionResults = null;
        this.lastVectorsWithRareResponses = null;
        this.secondVectorsWithRareResponses = null;
    }

    private <V extends TicketVector, T extends TestInfo> List<V>
        getVectorsWithRareResponses(InformationLeakTest<T> leakTest, Class<V> vectorClass, int maxOccurences) {
        List<V> ret = new ArrayList<>();
        for (VectorResponse response : SessionTicketPaddingOracleProbe.getRareResponses(leakTest, maxOccurences)) {
            ret.add(vectorClass.cast(response.getVector()));
        }
        return ret;
    }

    @Override
    public void writeToSiteReport(SiteReport report) {
        putResult(report, AnalyzedProperty.PADDING_ORACLE_TICKET, overallResult, true);
    }

    public TestResult getOverallResult() {
        return this.overallResult;
    }

    public List<TicketPaddingOracleOffsetResult> getPositionResults() {
        return this.positionResults;
    }

    public List<TicketPoVectorLast> getLastVectorsWithRareResponses() {
        return this.lastVectorsWithRareResponses;
    }

    public List<TicketPoVectorSecond> getSecondVectorsWithRareResponses() {
        return this.secondVectorsWithRareResponses;
    }

}
