/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.leak.info.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.result.PaddingOracleResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class PaddingOracleProbe extends TlsProbe {

    private static int numberOfIterations;
    private static int numberOfAddtionalIterations;

    private List<VersionSuiteListPair> serverSupportedSuites;

    public PaddingOracleProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.PADDING_ORACLE, config);
        this.numberOfIterations = scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL) ? 3 : 1;
        this.numberOfAddtionalIterations = scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL) ? 7 : 9;
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
                            PaddingOracleCommandConfig paddingOracleConfig
                                    = createPaddingOracleCommandConfig(pair.getVersion(), suite);
                            paddingOracleConfig.setVectorGeneratorType(vectorGeneratorType);
                            testResultList.add(getPaddingOracleInformationLeakTest(paddingOracleConfig));
                        }
                    }
                }
            }
        }
        LOGGER.debug("Finished evaluation");
        if (isPotentiallyVulnerable(testResultList)
                || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
            LOGGER.debug("Starting extended evaluation");
            for (InformationLeakTest<PaddingOracleTestInfo> fingerprint : testResultList) {
                if (fingerprint.isDistinctAnswers()
                        || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
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
        if (scannerConfig.getScanDetail() == ScannerDetail.ALL) {
            vectorTypeList.add(PaddingVectorGeneratorType.FINISHED);
            vectorTypeList.add(PaddingVectorGeneratorType.CLOSE_NOTIFY);
            vectorTypeList.add(PaddingVectorGeneratorType.FINISHED_RESUMPTION);
        }
        return vectorTypeList;
    }

    private PaddingOracleCommandConfig createPaddingOracleCommandConfig(ProtocolVersion version,
            CipherSuite cipherSuite) {
        PaddingOracleCommandConfig paddingOracleConfig
                = new PaddingOracleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) paddingOracleConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) paddingOracleConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        paddingOracleConfig.setNumberOfIterations(numberOfIterations);
        PaddingRecordGeneratorType recordGeneratorType;
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
            recordGeneratorType = PaddingRecordGeneratorType.SHORT;
        } else {
            recordGeneratorType = PaddingRecordGeneratorType.VERY_SHORT;
        }
        paddingOracleConfig.setRecordGeneratorType(recordGeneratorType);
        paddingOracleConfig.getCipherSuiteDelegate().setCipherSuites(cipherSuite);
        paddingOracleConfig.getProtocolVersionDelegate().setProtocolVersion(version);
        return paddingOracleConfig;
    }

    private InformationLeakTest<PaddingOracleTestInfo>
            getPaddingOracleInformationLeakTest(PaddingOracleCommandConfig paddingOracleConfig) {
        PaddingOracleAttacker attacker
                = new PaddingOracleAttacker(paddingOracleConfig, scannerConfig.createConfig(), getParallelExecutor());
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            attacker.setAdditionalTimeout(1000);
            attacker.setIncreasingTimeout(true);
        } else {
            attacker.setAdditionalTimeout(50);
        }
        attacker.isVulnerable();

        return new InformationLeakTest<>(
                new PaddingOracleTestInfo(paddingOracleConfig.getProtocolVersionDelegate().getProtocolVersion(),
                        paddingOracleConfig.getCipherSuiteDelegate().getCipherSuites().get(0),
                        paddingOracleConfig.getVectorGeneratorType(), paddingOracleConfig.getRecordGeneratorType()),
                attacker.getResponseMapList());
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
        PaddingOracleCommandConfig paddingOracleCommandConfig = createPaddingOracleCommandConfig(
                informationLeakTest.getTestInfo().getVersion(), informationLeakTest.getTestInfo().getCipherSuite());
        paddingOracleCommandConfig.setRecordGeneratorType(informationLeakTest.getTestInfo().getRecordGeneratorType());
        paddingOracleCommandConfig.setVectorGeneratorType(informationLeakTest.getTestInfo().getVectorGeneratorType());
        paddingOracleCommandConfig.setNumberOfIterations(numberOfAdditionalIterations);
        InformationLeakTest<PaddingOracleTestInfo> intermediateResponseMap
                = getPaddingOracleInformationLeakTest(paddingOracleCommandConfig);
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
