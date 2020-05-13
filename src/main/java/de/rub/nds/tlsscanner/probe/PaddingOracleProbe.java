/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttacker;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.leak.InformationLeakTest;
import de.rub.nds.tlsscanner.leak.info.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.report.result.PaddingOracleResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PaddingOracleProbe extends TlsProbe {

    private List<VersionSuiteListPair> serverSupportedSuites;

    public PaddingOracleProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.PADDING_ORACLE, config, 9);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<PaddingVectorGeneratorType> vectorTypeList = createVectorTypeList();
            List<InformationLeakTest<PaddingOracleTestInfo>> testResultList = new LinkedList<>();
            for (PaddingVectorGeneratorType vectorGeneratorType : vectorTypeList) {
                for (VersionSuiteListPair pair : serverSupportedSuites) {
                    if (pair.getVersion() == ProtocolVersion.TLS10 || pair.getVersion() == ProtocolVersion.TLS11
                            || pair.getVersion() == ProtocolVersion.TLS12) {
                        for (CipherSuite suite : pair.getCiphersuiteList()) {
                            if (suite.isCBC() && CipherSuite.getImplemented().contains(suite)) {
                                PaddingOracleCommandConfig paddingOracleConfig = createPaddingOracleCommandConfig(
                                        pair.getVersion(), suite);
                                paddingOracleConfig.setVectorGeneratorType(vectorGeneratorType);
                                testResultList.add(getPaddingOracleInformationLeakTest(paddingOracleConfig));
                            }
                        }
                    }
                }
            }
            // If we found some difference in the server behavior we need to
            if (isPotentiallyVulnerable(testResultList)
                    || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
                LOGGER.debug("We found non-determinism during the padding oracle scan");
                LOGGER.debug("Starting non-determinism evaluation");
                for (InformationLeakTest<PaddingOracleTestInfo> fingerprint : testResultList) {
                    if (fingerprint.isDistinctAnswers()
                            || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                        LOGGER.debug("Found a candidate for the non-determinism eval:"
                                + fingerprint.getTestInfo().getCipherSuite() + " - "
                                + fingerprint.getTestInfo().getCipherSuite());
                        extendFingerPrint(fingerprint, 7);
                    }
                }
                LOGGER.debug("Finished non-determinism evaluation");
            }
            return new PaddingOracleResult(testResultList);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new PaddingOracleResult(new LinkedList<>());
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

    private PaddingOracleCommandConfig createPaddingOracleCommandConfig(ProtocolVersion version, CipherSuite cipherSuite) {
        PaddingOracleCommandConfig paddingOracleConfig = new PaddingOracleCommandConfig(getScannerConfig()
                .getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) paddingOracleConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) paddingOracleConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        PaddingRecordGeneratorType recordGeneratorType;
        paddingOracleConfig.setNumberOfIterations(2);
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
            recordGeneratorType = PaddingRecordGeneratorType.SHORT;
            paddingOracleConfig.setNumberOfIterations(3);
        } else {
            recordGeneratorType = PaddingRecordGeneratorType.VERY_SHORT;
            paddingOracleConfig.setNumberOfIterations(1);
        }
        paddingOracleConfig.setRecordGeneratorType(recordGeneratorType);
        paddingOracleConfig.getCiphersuiteDelegate().setCipherSuites(cipherSuite);
        paddingOracleConfig.getProtocolVersionDelegate().setProtocolVersion(version);
        return paddingOracleConfig;
    }

    private InformationLeakTest<PaddingOracleTestInfo> getPaddingOracleInformationLeakTest(
            PaddingOracleCommandConfig paddingOracleConfig) {
        PaddingOracleAttacker attacker = new PaddingOracleAttacker(paddingOracleConfig, scannerConfig.createConfig(),
                getParallelExecutor());
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            attacker.setAdditionalTimeout(1000);
            attacker.setIncreasingTimeout(true);
        } else {
            attacker.setAdditionalTimeout(50);
        }
        try {
            attacker.isVulnerable();
        } catch (Exception E) {
            LOGGER.error("Encountered an exception while testing for PaddingOracles", E);
        }

        return new InformationLeakTest<>(new PaddingOracleTestInfo(paddingOracleConfig.getProtocolVersionDelegate()
                .getProtocolVersion(), paddingOracleConfig.getCiphersuiteDelegate().getCipherSuites().get(0),
                paddingOracleConfig.getVectorGeneratorType(), paddingOracleConfig.getRecordGeneratorType()),
                attacker.getResponseMapList());
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (!(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0), TestResult.TRUE))
                && !(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1), TestResult.TRUE))
                && !(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2), TestResult.TRUE))) {
            return false;
        }
        // TODO TLS13 probe is only a dependency to prevent an
        // java.util.ConcurrentModificationException. Not good
        // needs to be fixed before merging!
        if (!report.isProbeAlreadyExecuted(ProbeType.CIPHERSUITE) || !report.isProbeAlreadyExecuted(ProbeType.TLS13)) {
            return false;
        }
        return Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS), TestResult.TRUE);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new PaddingOracleResult(null);
    }

    private void extendFingerPrint(InformationLeakTest<PaddingOracleTestInfo> informationLeakTest,
            int numberOfAdditionalIterations) {
        PaddingOracleCommandConfig paddingOracleCommandConfig = createPaddingOracleCommandConfig(informationLeakTest
                .getTestInfo().getVersion(), informationLeakTest.getTestInfo().getCipherSuite());
        paddingOracleCommandConfig.setRecordGeneratorType(informationLeakTest.getTestInfo().getRecordGeneratorType());
        paddingOracleCommandConfig.setVectorGeneratorType(informationLeakTest.getTestInfo().getVectorGeneratorType());
        paddingOracleCommandConfig.setNumberOfIterations(numberOfAdditionalIterations);
        InformationLeakTest intermediateResponseMap = getPaddingOracleInformationLeakTest(paddingOracleCommandConfig);
        informationLeakTest.extendTest(intermediateResponseMap.getVectorContainerList());

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
