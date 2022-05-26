/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.leak.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.PaddingOracleAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingOracleProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private TestResult vulnerable;

    private static final int NUMBER_OF_ITERATIONS = 3;
    private static final int NUMBER_OF_ITERATIONS_IN_QUICK_MODE = 1;
    private static final int NUMBER_OF_ADDTIONAL_ITERATIONS = 7;
    private static final int NUMBER_OF_ADDTIONAL_ITERATIONS_IN_QUICK_MODE = 9;

    private final ScannerDetail scanDetail;
    private final int numberOfIterations;
    private final int numberOfAddtionalIterations;

    private List<VersionSuiteListPair> serverSupportedSuites;
    private List<InformationLeakTest<PaddingOracleTestInfo>> resultList;

    public PaddingOracleProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.PADDING_ORACLE, configSelector);
        scanDetail = configSelector.getScannerConfig().getScanDetail();
        numberOfIterations = scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL) ? NUMBER_OF_ITERATIONS
            : NUMBER_OF_ITERATIONS_IN_QUICK_MODE;
        numberOfAddtionalIterations = scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL) ? NUMBER_OF_ADDTIONAL_ITERATIONS
            : NUMBER_OF_ADDTIONAL_ITERATIONS_IN_QUICK_MODE;
        super.register(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE,
            TlsAnalyzedProperty.LIST_PADDINGORACLE_TESTRESULTS);
    }

    @Override
    public void executeTest() {
        LOGGER.debug("Starting evaluation");
        List<PaddingVectorGeneratorType> vectorTypeList = createVectorTypeList();
        resultList = new LinkedList<>();
        for (PaddingVectorGeneratorType vectorGeneratorType : vectorTypeList) {
            for (VersionSuiteListPair pair : serverSupportedSuites) {
                if (!pair.getVersion().isSSL() && !pair.getVersion().isTLS13()) {
                    for (CipherSuite suite : pair.getCipherSuiteList()) {
                        if (!suite.isPsk() && suite.isCBC() && CipherSuite.getImplemented().contains(suite)) {
                            PaddingRecordGeneratorType recordGeneratorType =
                                scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL) ? PaddingRecordGeneratorType.SHORT
                                    : PaddingRecordGeneratorType.VERY_SHORT;
                            resultList.add(getPaddingOracleInformationLeakTest(vectorGeneratorType, recordGeneratorType,
                                numberOfIterations, pair.getVersion(), suite));
                        }
                    }
                }
            }
        }
        LOGGER.debug("Finished evaluation");
        if (isPotentiallyVulnerable(resultList) || scanDetail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
            LOGGER.debug("Starting extended evaluation");
            for (InformationLeakTest<PaddingOracleTestInfo> fingerprint : resultList) {
                if (fingerprint.isDistinctAnswers() || scanDetail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                    extendFingerPrint(fingerprint, numberOfAddtionalIterations);
                }
            }
            LOGGER.debug("Finished extended evaluation");
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
        PaddingVectorGeneratorType vectorGeneratorType, PaddingRecordGeneratorType paddingRecordGeneratorType,
        int numberOfIterations, ProtocolVersion testedVersion, CipherSuite testedSuite) {
        PaddingOracleAttacker attacker =
            new PaddingOracleAttacker(configSelector.getBaseConfig(), getParallelExecutor(), paddingRecordGeneratorType,
                vectorGeneratorType, numberOfIterations, testedVersion, testedSuite);
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
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION)
            .requireAnalyzedProperties(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void adjustConfig(ServerReport report) {
        serverSupportedSuites = ((ListResult<VersionSuiteListPair>) report.getResultMap()
            .get(TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS.name())).getList();
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
        for (InformationLeakTest<?> fingerprint : testResultList) {
            if (fingerprint.isDistinctAnswers()) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (resultList != null) {
            vulnerable = TestResults.FALSE;
            for (InformationLeakTest<?> informationLeakTest : resultList) {
                if (informationLeakTest.isSignificantDistinctAnswers())
                    vulnerable = TestResults.TRUE;
            }
        } else
            vulnerable = TestResults.ERROR_DURING_TEST;
        super.put(TlsAnalyzedProperty.LIST_PADDINGORACLE_TESTRESULTS,
            new ListResult<InformationLeakTest<PaddingOracleTestInfo>>(resultList, "PADDINGORACLE_TESTRESULTS"));
        super.put(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, vulnerable);
    }
}
