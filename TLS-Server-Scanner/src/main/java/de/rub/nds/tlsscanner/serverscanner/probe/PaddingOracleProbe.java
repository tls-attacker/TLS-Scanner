/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.leak.info.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.PaddingOracleAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.PaddingOracleResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class PaddingOracleProbe extends TlsProbe {

    private final ScannerDetail scanDetail;
    private static int numberOfIterations;
    private static int numberOfAddtionalIterations;

    private List<VersionSuiteListPair> serverSupportedSuites;

    public PaddingOracleProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.PADDING_ORACLE, configSelector);
        scanDetail = getConfigSelector().getScannerConfig().getScanDetail();
        numberOfIterations = scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL) ? 3 : 1;
        numberOfAddtionalIterations = scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL) ? 7 : 9;
    }

    @Override
    public ProbeResult executeTest() {
        LOGGER.debug("Starting evaluation");
        List<PaddingVectorGeneratorType> vectorTypeList = createVectorTypeList();
        List<InformationLeakTest<PaddingOracleTestInfo>> testResultList = new LinkedList<>();
        for (PaddingVectorGeneratorType vectorGeneratorType : vectorTypeList) {
            for (VersionSuiteListPair pair : serverSupportedSuites) {
                if (!pair.getVersion().isSSL() && !pair.getVersion().isTLS13()) {
                    for (CipherSuite suite : pair.getCipherSuiteList()) {
                        if (!suite.isPsk() && suite.isCBC() && CipherSuite.getImplemented().contains(suite)) {
                            PaddingRecordGeneratorType recordGeneratorType =
                                scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL) ? PaddingRecordGeneratorType.SHORT
                                    : PaddingRecordGeneratorType.VERY_SHORT;
                            testResultList.add(getPaddingOracleInformationLeakTest(vectorGeneratorType,
                                recordGeneratorType, numberOfIterations, pair.getVersion(), suite));
                        }
                    }
                }
            }
        }
        LOGGER.debug("Finished evaluation");
        if (isPotentiallyVulnerable(testResultList) || scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
            LOGGER.debug("Starting extended evaluation");
            for (InformationLeakTest<PaddingOracleTestInfo> fingerprint : testResultList) {
                if (fingerprint.isDistinctAnswers() || scanDetail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                    extendFingerPrint(fingerprint, numberOfAddtionalIterations);
                }
            }
            LOGGER.debug("Finished extended evaluation");
        }
        return new PaddingOracleResult(testResultList);
    }

    private List<PaddingVectorGeneratorType> createVectorTypeList() {
        List<PaddingVectorGeneratorType> vectorTypeList = new LinkedList<>();
        vectorTypeList.add(PaddingVectorGeneratorType.CLASSIC_DYNAMIC);
        if (scanDetail == ScannerDetail.ALL) {
            vectorTypeList.add(PaddingVectorGeneratorType.FINISHED);
            vectorTypeList.add(PaddingVectorGeneratorType.CLOSE_NOTIFY);
            vectorTypeList.add(PaddingVectorGeneratorType.FINISHED_RESUMPTION);
        }
        return vectorTypeList;
    }

    private InformationLeakTest<PaddingOracleTestInfo> getPaddingOracleInformationLeakTest(
        PaddingVectorGeneratorType vectorGeneratorType, PaddingRecordGeneratorType paddingRecordGeneratorType,
        int numberOfIterations, ProtocolVersion testedVersion, CipherSuite testedSuite) {
        PaddingOracleAttacker attacker =
            new PaddingOracleAttacker(getConfigSelector().getBaseConfig(), getParallelExecutor(),
                paddingRecordGeneratorType, vectorGeneratorType, numberOfIterations, testedVersion, testedSuite);
        if (scanDetail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            attacker.setAdditionalTimeout(1000);
            attacker.setIncreasingTimeout(true);
        } else {
            attacker.setAdditionalTimeout(50);
        }
        attacker.isVulnerable();
        return new InformationLeakTest<>(
            new PaddingOracleTestInfo(testedVersion, testedSuite, vectorGeneratorType, paddingRecordGeneratorType),
            attacker.getFullResponseMap());
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.isProbeAlreadyExecuted(ProbeType.CIPHER_SUITE)
            && report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)) {
            return Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS), TestResult.TRUE);
        } else {
            return false;
        }
    }

    @Override
    public void adjustConfig(SiteReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new PaddingOracleResult(TestResult.COULD_NOT_TEST);
    }

    private void extendFingerPrint(InformationLeakTest<PaddingOracleTestInfo> informationLeakTest,
        int numberOfAdditionalIterations) {
        InformationLeakTest<PaddingOracleTestInfo> intermediateResponseMap =
            getPaddingOracleInformationLeakTest(informationLeakTest.getTestInfo().getVectorGeneratorType(),
                informationLeakTest.getTestInfo().getRecordGeneratorType(), numberOfAdditionalIterations,
                informationLeakTest.getTestInfo().getVersion(), informationLeakTest.getTestInfo().getCipherSuite());
        informationLeakTest.extendTestWithVectorContainers(intermediateResponseMap.getVectorContainerList());

    }

    private boolean isPotentiallyVulnerable(List<InformationLeakTest<PaddingOracleTestInfo>> testResultList) {
        for (InformationLeakTest fingerprint : testResultList) {
            if (fingerprint.isDistinctAnswers()) {
                return true;
            }
        }
        return false;
    }
}
