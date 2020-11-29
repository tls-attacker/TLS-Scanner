/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttacker;
import de.rub.nds.tlsattacker.attacks.constants.BleichenbacherWorkflowType;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.leak.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.leak.info.BleichenbacherOracleTestInfo;
import static de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.BleichenbacherResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BleichenbacherProbe extends TlsProbe {

    private List<VersionSuiteListPair> serverSupportedSuites;

    public BleichenbacherProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.BLEICHENBACHER, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<BleichenbacherWorkflowType> workflowTypeList = createWorkflowTypeList();
            List<InformationLeakTest<BleichenbacherOracleTestInfo>> testResultList = new LinkedList<>();
            for (BleichenbacherWorkflowType workflowType : workflowTypeList) {
                for (VersionSuiteListPair pair : serverSupportedSuites) {
                    if (pair.getVersion() == ProtocolVersion.TLS10 || pair.getVersion() == ProtocolVersion.TLS11
                            || pair.getVersion() == ProtocolVersion.TLS12
                            || pair.getVersion() == ProtocolVersion.DTLS10
                            || pair.getVersion() == ProtocolVersion.DTLS12) {
                        for (CipherSuite suite : pair.getCiphersuiteList()) {
                            if (suite.isCBC() && CipherSuite.getImplemented().contains(suite)) {
                                BleichenbacherCommandConfig bleichenbacherConfig = createBleichenbacherCommandConfig(
                                        pair.getVersion(), suite);
                                bleichenbacherConfig.setWorkflowType(workflowType);
                                testResultList.add(getBleichenbacherOracleInformationLeakTest(bleichenbacherConfig));
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
                for (InformationLeakTest<BleichenbacherOracleTestInfo> fingerprint : testResultList) {
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
            return new BleichenbacherResult(testResultList);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new BleichenbacherResult(TestResult.ERROR_DURING_TEST);
        }
    }

    private List<BleichenbacherWorkflowType> createWorkflowTypeList() {
        List<BleichenbacherWorkflowType> vectorTypeList = new LinkedList<>();
        vectorTypeList.add(BleichenbacherWorkflowType.CKE_CCS_FIN);
        if (scannerConfig.getScanDetail() == ScannerDetail.ALL) {
            vectorTypeList.add(BleichenbacherWorkflowType.CKE);
            vectorTypeList.add(BleichenbacherWorkflowType.CKE_CCS);
            vectorTypeList.add(BleichenbacherWorkflowType.CKE_FIN);
        }
        return vectorTypeList;
    }

    private BleichenbacherCommandConfig createBleichenbacherCommandConfig(ProtocolVersion version,
            CipherSuite cipherSuite) {
        BleichenbacherCommandConfig bleichenbacherConfig = new BleichenbacherCommandConfig(getScannerConfig()
                .getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) bleichenbacherConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) bleichenbacherConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        BleichenbacherCommandConfig.Type recordGeneratorType;
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.ALL)) {
            recordGeneratorType = BleichenbacherCommandConfig.Type.FULL;
            bleichenbacherConfig.setNumberOfIterations(3);
        } else if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
            recordGeneratorType = BleichenbacherCommandConfig.Type.FAST;
            bleichenbacherConfig.setNumberOfIterations(3);
        } else {
            recordGeneratorType = BleichenbacherCommandConfig.Type.FAST;
            bleichenbacherConfig.setNumberOfIterations(1);
        }
        bleichenbacherConfig.setType(recordGeneratorType);
        bleichenbacherConfig.getCiphersuiteDelegate().setCipherSuites(cipherSuite);
        bleichenbacherConfig.getProtocolVersionDelegate().setProtocolVersion(version);
        return bleichenbacherConfig;
    }

    private InformationLeakTest<BleichenbacherOracleTestInfo> getBleichenbacherOracleInformationLeakTest(
            BleichenbacherCommandConfig bleichenbacherConfig) {
        BleichenbacherAttacker attacker = new BleichenbacherAttacker(bleichenbacherConfig,
                scannerConfig.createConfig(), getParallelExecutor());
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            attacker.setAdditionalTimeout(1000);
            attacker.setIncreasingTimeout(true);
        } else {
            attacker.setAdditionalTimeout(50);
        }
        try {
            attacker.isVulnerable();
        } catch (Exception E) {
            LOGGER.error("Encountered an exception while testing for BleichenbacherOracles", E);
        }
        LOGGER.warn(bleichenbacherConfig.getWorkflowType() + "; " + bleichenbacherConfig.getType() + "; "
                + bleichenbacherConfig.getNumberOfIterations() + " Iterationen; "
                + attacker.getResponseMapList().size() + " Fingerprints;");
        return new InformationLeakTest<>(new BleichenbacherOracleTestInfo(bleichenbacherConfig
                .getProtocolVersionDelegate().getProtocolVersion(), bleichenbacherConfig.getCiphersuiteDelegate()
                .getCipherSuites().get(0), bleichenbacherConfig.getWorkflowType(), bleichenbacherConfig.getType()),
                attacker.getResponseMapList());
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.isProbeAlreadyExecuted(ProbeType.CIPHERSUITE)
                && report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)) {
            return Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_RSA), TestResult.TRUE);
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
        return new BleichenbacherResult(TestResult.COULD_NOT_TEST);
    }

    private void extendFingerPrint(InformationLeakTest<BleichenbacherOracleTestInfo> informationLeakTest,
            int numberOfAdditionalIterations) {
        BleichenbacherCommandConfig bleichenbacherConfig = createBleichenbacherCommandConfig(informationLeakTest
                .getTestInfo().getVersion(), informationLeakTest.getTestInfo().getCipherSuite());
        bleichenbacherConfig.setType(informationLeakTest.getTestInfo().getBleichenbacherType());
        bleichenbacherConfig.setWorkflowType(informationLeakTest.getTestInfo().getBleichenbacherWorkflowType());
        bleichenbacherConfig.setNumberOfIterations(numberOfAdditionalIterations);
        InformationLeakTest<BleichenbacherOracleTestInfo> intermediateResponseMap = getBleichenbacherOracleInformationLeakTest(bleichenbacherConfig);
        informationLeakTest.extendTestWithVectorContainers(intermediateResponseMap.getVectorContainerList());
    }

    private boolean isPotentiallyVulnerable(List<InformationLeakTest<BleichenbacherOracleTestInfo>> testResultList) {
        for (InformationLeakTest fingerprint : testResultList) {
            if (fingerprint.isDistinctAnswers()) {
                return true;
            }
        }
        return false;
    }
}
