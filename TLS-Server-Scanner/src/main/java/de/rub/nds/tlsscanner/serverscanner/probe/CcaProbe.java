/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateManager;
import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateType;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.attacks.cca.vector.CcaTaskVectorPair;
import de.rub.nds.tlsattacker.attacks.cca.vector.CcaVector;
import de.rub.nds.tlsattacker.attacks.task.CcaTask;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.CcaResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.result.cca.CcaTestResult;
import java.util.LinkedList;
import java.util.List;

public class CcaProbe extends TlsProbe {
    private List<VersionSuiteListPair> versionSuiteListPairsList;

    private boolean increasingTimeout = false;

    private long additionalTimeout = 10000;

    private long additionalTcpTimeout = 1000;

    private int reexecutions = 3;

    public CcaProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CCA, config);
        versionSuiteListPairsList = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {

        ParallelExecutor parallelExecutor = getParallelExecutor();

        CcaDelegate ccaDelegate = (CcaDelegate) getScannerConfig().getDelegate(CcaDelegate.class);

        CcaCertificateManager ccaCertificateManager = new CcaCertificateManager(ccaDelegate);

        List<ProtocolVersion> desiredVersions = new LinkedList<>();
        desiredVersions.add(ProtocolVersion.TLS11);
        desiredVersions.add(ProtocolVersion.TLS10);
        desiredVersions.add(ProtocolVersion.TLS12);

        List<VersionSuiteListPair> versionSuiteListPairs = getVersionSuitePairList(desiredVersions);

        if (versionSuiteListPairs.isEmpty()) {
            LOGGER.warn("No common cipher suites found. Can't continue scan.");
            return new CcaResult(TestResult.COULD_NOT_TEST, null);
        }

        Boolean haveClientCertificate = ccaDelegate.clientCertificateSupplied();
        Boolean gotDirectoryParameters = ccaDelegate.directoriesSupplied();

        List<TlsTask> taskList = new LinkedList<>();
        List<CcaTaskVectorPair> taskVectorPairList = new LinkedList<>();

        for (CcaWorkflowType ccaWorkflowType : CcaWorkflowType.values()) {
            for (CcaCertificateType ccaCertificateType : CcaCertificateType.values()) {
                /**
                 * Skip certificate types for which we are lacking the corresponding CLI parameters Additionally skip
                 * certificate types that aren't required. I.e. a flow not sending a certificate message can simply run
                 * once with the CcaCertificateType EMPTY
                 */
                if ((ccaCertificateType.getRequiresCertificate() && !haveClientCertificate)
                    || (ccaCertificateType.getRequiresCaCertAndKeys() && !gotDirectoryParameters)
                    || (!ccaWorkflowType.getRequiresCertificate() && ccaCertificateType != CcaCertificateType.EMPTY)) {
                    continue;
                }
                for (VersionSuiteListPair versionSuiteListPair : versionSuiteListPairs) {
                    for (CipherSuite cipherSuite : versionSuiteListPair.getCipherSuiteList()) {

                        CcaVector ccaVector = new CcaVector(versionSuiteListPair.getVersion(), cipherSuite,
                            ccaWorkflowType, ccaCertificateType);
                        Config tlsConfig = generateConfig();
                        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuite);
                        tlsConfig.setHighestProtocolVersion(versionSuiteListPair.getVersion());

                        CcaTask ccaTask = new CcaTask(ccaVector, tlsConfig, ccaCertificateManager, additionalTimeout,
                            increasingTimeout, reexecutions, additionalTcpTimeout);
                        taskList.add(ccaTask);
                        taskVectorPairList.add(new CcaTaskVectorPair(ccaTask, ccaVector));
                    }
                }
            }
        }

        List<CcaTestResult> resultList = new LinkedList<>();
        Boolean handshakeSucceeded = false;
        parallelExecutor.bulkExecuteTasks(taskList);
        for (CcaTaskVectorPair ccaTaskVectorPair : taskVectorPairList) {
            if (ccaTaskVectorPair.getCcaTask().isHasError()) {
                LOGGER.warn("Failed to scan " + ccaTaskVectorPair);
            } else {
                Boolean vectorVulnerable = false;
                if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED,
                    ccaTaskVectorPair.getCcaTask().getState().getWorkflowTrace())) {
                    handshakeSucceeded = true;
                    vectorVulnerable = true;
                } else {
                    vectorVulnerable = false;
                }
                resultList.add(new CcaTestResult(vectorVulnerable, ccaTaskVectorPair.getVector().getCcaWorkflowType(),
                    ccaTaskVectorPair.getVector().getCcaCertificateType(),
                    ccaTaskVectorPair.getVector().getProtocolVersion(),
                    ccaTaskVectorPair.getVector().getCipherSuite()));
            }
        }

        return new CcaResult(handshakeSucceeded ? TestResult.TRUE : TestResult.FALSE, resultList);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if ((report.getResult(AnalyzedProperty.REQUIRES_CCA) == TestResult.TRUE)
            && (report.getVersionSuitePairs() != null)) {
            return true;
        }
        return false;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        this.versionSuiteListPairsList.addAll(report.getVersionSuitePairs());
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CcaResult(TestResult.COULD_NOT_TEST, null);
    }

    private Config generateConfig() {
        Config config = getScannerConfig().createConfig();
        config.setAutoSelectCertificate(false);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS10);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setClientAuthentication(true);

        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterIOException(true);
        config.setStopActionsAfterFatal(true);

        return config;
    }

    private List<VersionSuiteListPair> getVersionSuitePairList(List<ProtocolVersion> desiredVersions) {
        List<VersionSuiteListPair> versionSuiteListPairs = new LinkedList<>();
        for (VersionSuiteListPair versionSuiteListPair : this.versionSuiteListPairsList) {
            if (desiredVersions.contains(versionSuiteListPair.getVersion())) {
                versionSuiteListPairs.add(versionSuiteListPair);
            }
        }

        List<CipherSuite> implementedCipherSuites = CipherSuite.getImplemented();
        List<VersionSuiteListPair> versionSuiteListPairList;

        versionSuiteListPairList = getNonDetailedVersionSuitePairList(versionSuiteListPairs, implementedCipherSuites);
        if (versionSuiteListPairList.isEmpty()) {
            versionSuiteListPairList = getDetailedVersionSuitePairList(versionSuiteListPairs, implementedCipherSuites);
        }

        return versionSuiteListPairList;
    }

    private List<VersionSuiteListPair> getDetailedVersionSuitePairList(List<VersionSuiteListPair> versionSuiteListPairs,
        List<CipherSuite> implementedCipherSuites) {
        List<VersionSuiteListPair> versionSuiteListPairList = new LinkedList<>();
        for (VersionSuiteListPair versionSuiteListPair : versionSuiteListPairs) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            for (CipherSuite cipherSuite : versionSuiteListPair.getCipherSuiteList()) {
                if (implementedCipherSuites.contains(cipherSuite)) {
                    cipherSuites.add(cipherSuite);
                }
            }
            if (!cipherSuites.isEmpty()) {
                versionSuiteListPairList.add(new VersionSuiteListPair(versionSuiteListPair.getVersion(), cipherSuites));
            }
        }
        return versionSuiteListPairList;
    }

    private List<VersionSuiteListPair> getNonDetailedVersionSuitePairList(
        List<VersionSuiteListPair> versionSuiteListPairs, List<CipherSuite> implementedCipherSuites) {
        List<VersionSuiteListPair> versionSuiteListPairList = new LinkedList<>();
        if (!getScannerConfig().getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            for (VersionSuiteListPair versionSuiteListPair : versionSuiteListPairs) {
                List<CipherSuite> cipherSuites = new LinkedList<>();
                for (CipherSuite cipherSuite : versionSuiteListPair.getCipherSuiteList()) {
                    if (AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isKeyExchangeDh()
                        && implementedCipherSuites.contains(cipherSuite)) {
                        cipherSuites.add(cipherSuite);
                        break;
                    }
                }
                if (!cipherSuites.isEmpty()) {
                    versionSuiteListPairList
                        .add(new VersionSuiteListPair(versionSuiteListPair.getVersion(), cipherSuites));
                }
            }
        }
        return versionSuiteListPairList;
    }

}
