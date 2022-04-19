/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.vectorstatistics.InformationLeakTest;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.leak.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingOracleProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private TestResult vulnerable;

    private final int numberOfIterations;
    private final int numberOfAddtionalIterations;

    private List<VersionSuiteListPair> serverSupportedSuites;
    private List<InformationLeakTest<PaddingOracleTestInfo>> resultList;

    public PaddingOracleProbe(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.PADDING_ORACLE, config);
        this.numberOfIterations = scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL) ? 3 : 1;
        this.numberOfAddtionalIterations = scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL) ? 7 : 9;
        super.properties.add(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE);
    }

    @Override
    public void executeTest() {
        LOGGER.debug("Starting evaluation");
        List<PaddingVectorGeneratorType> vectorTypeList = createVectorTypeList();
        this.resultList = new LinkedList<>();
        for (PaddingVectorGeneratorType vectorGeneratorType : vectorTypeList) {
            for (VersionSuiteListPair pair : serverSupportedSuites) {
                if (!pair.getVersion().isSSL() && !pair.getVersion().isTLS13()) {
                    for (CipherSuite suite : pair.getCipherSuiteList()) {
                        if (!suite.isPsk() && suite.isCBC() && CipherSuite.getImplemented().contains(suite)) {
                            PaddingOracleCommandConfig paddingOracleConfig =
                                createPaddingOracleCommandConfig(pair.getVersion(), suite);
                            paddingOracleConfig.setVectorGeneratorType(vectorGeneratorType);
                            this.resultList.add(getPaddingOracleInformationLeakTest(paddingOracleConfig));
                        }
                    }
                }
            }
        }
        LOGGER.debug("Finished evaluation");
        if (isPotentiallyVulnerable(this.resultList)
            || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
            LOGGER.debug("Starting extended evaluation");
            for (InformationLeakTest<PaddingOracleTestInfo> fingerprint : this.resultList) {
                if (fingerprint.isDistinctAnswers()
                    || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                    extendFingerPrint(fingerprint, numberOfAddtionalIterations);
                }
            }
            LOGGER.debug("Finished extended evaluation");
        }
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
        PaddingOracleCommandConfig paddingOracleConfig =
            new PaddingOracleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) paddingOracleConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(scannerConfig.getClientDelegate().getHost());
        delegate.setSniHostname(scannerConfig.getClientDelegate().getSniHostname());
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
        PaddingOracleAttacker attacker =
            new PaddingOracleAttacker(paddingOracleConfig, scannerConfig.createConfig(), getParallelExecutor());
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
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION)
            .requireAnalyzedProperties(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    @Override
    public PaddingOracleProbe getCouldNotExecuteResult() {
        this.vulnerable = TestResults.COULD_NOT_TEST;
        return this;
    }

    private void extendFingerPrint(InformationLeakTest<PaddingOracleTestInfo> informationLeakTest,
        int numberOfAdditionalIterations) {
        PaddingOracleCommandConfig paddingOracleCommandConfig = createPaddingOracleCommandConfig(
            informationLeakTest.getTestInfo().getVersion(), informationLeakTest.getTestInfo().getCipherSuite());
        paddingOracleCommandConfig.setRecordGeneratorType(informationLeakTest.getTestInfo().getRecordGeneratorType());
        paddingOracleCommandConfig.setVectorGeneratorType(informationLeakTest.getTestInfo().getVectorGeneratorType());
        paddingOracleCommandConfig.setNumberOfIterations(numberOfAdditionalIterations);
        InformationLeakTest<PaddingOracleTestInfo> intermediateResponseMap =
            getPaddingOracleInformationLeakTest(paddingOracleCommandConfig);
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
        if (this.resultList != null) {
            this.vulnerable = TestResults.FALSE;
            for (InformationLeakTest<?> informationLeakTest : this.resultList) {
                if (informationLeakTest.isSignificantDistinctAnswers())
                    this.vulnerable = TestResults.TRUE;
            }
        } else
            this.vulnerable = TestResults.ERROR_DURING_TEST;
        report.setPaddingOracleTestResultList(this.resultList);
        super.setPropertyReportValue(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, this.vulnerable);
    }
}
