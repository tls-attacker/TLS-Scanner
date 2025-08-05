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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.leak.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.core.probe.padding.PaddingOracleAttacker;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingOracleProbe extends TlsServerProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private TestResult vulnerable = TestResults.COULD_NOT_TEST;

    private static final int NUMBER_OF_ITERATIONS = 3;
    private static final int NUMBER_OF_ITERATIONS_IN_QUICK_MODE = 1;
    private static final int NUMBER_OF_ADDTIONAL_ITERATIONS = 7;
    private static final int NUMBER_OF_ADDTIONAL_ITERATIONS_IN_QUICK_MODE = 9;

    private final ScannerDetail scanDetail;
    private final int numberOfIterations;
    private final int numberOfAddtionalIterations;

    private List<VersionSuiteListPair> serverSupportedSuites;
    private List<InformationLeakTest<PaddingOracleTestInfo>> resultList = new LinkedList<>();

    public PaddingOracleProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.PADDING_ORACLE, configSelector);
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
                TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE,
                TlsAnalyzedProperty.PADDING_ORACLE_TEST_RESULT);
    }

    @Override
    protected void executeTest() {
        LOGGER.debug("Starting evaluation");
        List<PaddingVectorGeneratorType> vectorTypeList = createVectorTypeList();
        resultList = new LinkedList<>();
        for (PaddingVectorGeneratorType vectorGeneratorType : vectorTypeList) {
            for (VersionSuiteListPair pair : serverSupportedSuites) {
                if (!pair.getVersion().isSSL() && !pair.getVersion().isTLS13()) {
                    for (CipherSuite suite : pair.getCipherSuiteList()) {
                        if (!suite.isPsk()
                                && suite.isCBC()
                                && CipherSuite.getImplemented().contains(suite)) {
                            PaddingRecordGeneratorType recordGeneratorType =
                                    scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL)
                                            ? PaddingRecordGeneratorType.SHORT
                                            : PaddingRecordGeneratorType.VERY_SHORT;
                            resultList.add(
                                    getPaddingOracleInformationLeakTest(
                                            vectorGeneratorType,
                                            recordGeneratorType,
                                            numberOfIterations,
                                            pair.getVersion(),
                                            suite));
                        }
                    }
                }
            }
        }
        LOGGER.debug("Finished evaluation");
        if (isPotentiallyVulnerable(resultList)
                || scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
            LOGGER.debug("Starting extended evaluation");
            for (InformationLeakTest<PaddingOracleTestInfo> fingerprint : resultList) {
                if (fingerprint.isDistinctAnswers()
                        || scanDetail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                    extendFingerPrint(fingerprint, numberOfAddtionalIterations);
                }
            }
            LOGGER.debug("Finished extended evaluation");
        }
        vulnerable = TestResults.FALSE;
        for (InformationLeakTest<?> informationLeakTest : resultList) {
            if (informationLeakTest.isSignificantDistinctAnswers()) {
                vulnerable = TestResults.TRUE;
            }
        }
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
            PaddingVectorGeneratorType vectorGeneratorType,
            PaddingRecordGeneratorType paddingRecordGeneratorType,
            int numberOfIterations,
            ProtocolVersion testedVersion,
            CipherSuite testedSuite) {
        PaddingOracleAttacker attacker =
                new PaddingOracleAttacker(
                        configSelector.getBaseConfig(),
                        getParallelExecutor(),
                        paddingRecordGeneratorType,
                        vectorGeneratorType,
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
                new PaddingOracleTestInfo(
                        testedVersion,
                        testedSuite,
                        vectorGeneratorType,
                        paddingRecordGeneratorType),
                attacker.getFullResponseMap());
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(
                        TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION)
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS));
    }

    @Override
    public void adjustConfig(ServerReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    private void extendFingerPrint(
            InformationLeakTest<PaddingOracleTestInfo> informationLeakTest,
            int numberOfAdditionalIterations) {
        InformationLeakTest<PaddingOracleTestInfo> intermediateResponseMap =
                getPaddingOracleInformationLeakTest(
                        informationLeakTest.getTestInfo().getVectorGeneratorType(),
                        informationLeakTest.getTestInfo().getRecordGeneratorType(),
                        numberOfAdditionalIterations,
                        informationLeakTest.getTestInfo().getVersion(),
                        informationLeakTest.getTestInfo().getCipherSuite());
        informationLeakTest.extendTestWithVectorContainers(
                intermediateResponseMap.getVectorContainerList());
    }

    private boolean isPotentiallyVulnerable(
            List<InformationLeakTest<PaddingOracleTestInfo>> testResultList) {
        for (InformationLeakTest<?> fingerprint : testResultList) {
            if (fingerprint.isDistinctAnswers()) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.PADDING_ORACLE_TEST_RESULT, resultList);
        put(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, vulnerable);
    }
}
