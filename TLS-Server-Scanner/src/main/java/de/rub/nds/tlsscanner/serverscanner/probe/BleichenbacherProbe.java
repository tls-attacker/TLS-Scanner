/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.leak.BleichenbacherOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.BleichenbacherAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherScanType;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;

public class BleichenbacherProbe extends TlsServerProbe {

    private static final int NUMBER_OF_ITERATIONS = 3;
    private static final int NUMBER_OF_ITERATIONS_IN_QUICK_MODE = 1;
    private static final int NUMBER_OF_ADDTIONAL_ITERATIONS = 7;
    private static final int NUMBER_OF_ADDTIONAL_ITERATIONS_IN_QUICK_MODE = 9;

    private final ScannerDetail scanDetail;
    private final int numberOfIterations;
    private final int numberOfAddtionalIterations;

    private List<VersionSuiteListPair> serverSupportedSuites;

    private List<InformationLeakTest<BleichenbacherOracleTestInfo>> testResultList =
            new LinkedList<>();

    private TestResult vulnerable = TestResults.COULD_NOT_TEST;

    public BleichenbacherProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.BLEICHENBACHER, configSelector);
        scanDetail = configSelector.getScannerConfig().getExecutorConfig().getScanDetail();
        numberOfIterations =
                scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL)
                        ? NUMBER_OF_ITERATIONS
                        : NUMBER_OF_ITERATIONS_IN_QUICK_MODE;
        numberOfAddtionalIterations =
                scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL)
                        ? NUMBER_OF_ADDTIONAL_ITERATIONS
                        : NUMBER_OF_ADDTIONAL_ITERATIONS_IN_QUICK_MODE;
        register(
                TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER,
                TlsAnalyzedProperty.BLEICHENBACHER_TEST_RESULT);
    }

    @Override
    protected void executeTest() {
        LOGGER.debug("Starting evaluation");
        List<BleichenbacherWorkflowType> workflowTypeList = createWorkflowTypeList();
        testResultList = new LinkedList<>();
        for (BleichenbacherWorkflowType workflowType : workflowTypeList) {
            for (VersionSuiteListPair pair : serverSupportedSuites) {
                if (!pair.getVersion().isSSL() && !pair.getVersion().isTLS13()) {
                    for (CipherSuite suite : pair.getCipherSuiteList()) {
                        if (AlgorithmResolver.getKeyExchangeAlgorithm(suite)
                                        == KeyExchangeAlgorithm.RSA
                                && CipherSuite.getImplemented().contains(suite)) {
                            BleichenbacherScanType recordGeneratorType =
                                    scanDetail.isGreaterEqualTo(ScannerDetail.ALL)
                                            ? BleichenbacherScanType.FULL
                                            : BleichenbacherScanType.FAST;
                            testResultList.add(
                                    getBleichenbacherOracleInformationLeakTest(
                                            recordGeneratorType,
                                            workflowType,
                                            numberOfIterations,
                                            pair.getVersion(),
                                            suite));
                        }
                    }
                }
            }
        }
        LOGGER.debug("Finished evaluation");
        if (isPotentiallyVulnerable(testResultList)
                || scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
            LOGGER.debug("Starting extended evaluation");
            for (InformationLeakTest<BleichenbacherOracleTestInfo> fingerprint : testResultList) {
                if (fingerprint.isDistinctAnswers()
                        || scanDetail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                    extendFingerPrint(fingerprint, numberOfAddtionalIterations);
                }
            }
            LOGGER.debug("Finished extended evaluation");
        }
        vulnerable = TestResults.FALSE;
        for (InformationLeakTest<?> informationLeakTest : testResultList) {
            if (informationLeakTest.isSignificantDistinctAnswers()) {
                vulnerable = TestResults.TRUE;
            }
        }
    }

    private List<BleichenbacherWorkflowType> createWorkflowTypeList() {
        List<BleichenbacherWorkflowType> vectorTypeList = new LinkedList<>();
        vectorTypeList.add(BleichenbacherWorkflowType.CKE_CCS_FIN);
        vectorTypeList.add(BleichenbacherWorkflowType.CKE);
        vectorTypeList.add(BleichenbacherWorkflowType.CKE_CCS);
        if (scanDetail == ScannerDetail.ALL) {
            vectorTypeList.add(BleichenbacherWorkflowType.CKE_FIN);
        }
        return vectorTypeList;
    }

    private InformationLeakTest<BleichenbacherOracleTestInfo>
            getBleichenbacherOracleInformationLeakTest(
                    BleichenbacherScanType scanType,
                    BleichenbacherWorkflowType workflowType,
                    int numberOfIterations,
                    ProtocolVersion testedVersion,
                    CipherSuite testedSuite) {
        BleichenbacherAttacker attacker =
                new BleichenbacherAttacker(
                        configSelector.getBaseConfig(),
                        getParallelExecutor(),
                        scanType,
                        workflowType,
                        numberOfIterations,
                        testedVersion,
                        testedSuite);
        if (scanDetail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            attacker.setAdditionalTimeout(1000);
            attacker.setIncreasingTimeout(true);
        } else {
            attacker.setAdditionalTimeout(50);
        }
        attacker.isVulnerable();
        return new InformationLeakTest<>(
                new BleichenbacherOracleTestInfo(
                        testedVersion, testedSuite, workflowType, scanType),
                attacker.getFullResponseMap());
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(
                        TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION)
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_RSA));
    }

    @Override
    public void adjustConfig(ServerReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    private void extendFingerPrint(
            InformationLeakTest<BleichenbacherOracleTestInfo> informationLeakTest,
            int numberOfAdditionalIterations) {
        InformationLeakTest<BleichenbacherOracleTestInfo> intermediateResponseMap =
                getBleichenbacherOracleInformationLeakTest(
                        informationLeakTest.getTestInfo().getBleichenbacherType(),
                        informationLeakTest.getTestInfo().getBleichenbacherWorkflowType(),
                        numberOfAdditionalIterations,
                        informationLeakTest.getTestInfo().getVersion(),
                        informationLeakTest.getTestInfo().getCipherSuite());
        informationLeakTest.extendTestWithVectorContainers(
                intermediateResponseMap.getVectorContainerList());
    }

    private boolean isPotentiallyVulnerable(
            List<InformationLeakTest<BleichenbacherOracleTestInfo>> testResultList) {
        for (InformationLeakTest<?> fingerprint : testResultList) {
            if (fingerprint.isDistinctAnswers()) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER, vulnerable);
        put(TlsAnalyzedProperty.BLEICHENBACHER_TEST_RESULT, testResultList);
    }
}
