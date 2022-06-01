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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.CcaCertificateManager;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaCertificateType;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.vector.CcaTaskVectorPair;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.vector.CcaVector;
import de.rub.nds.tlsscanner.serverscanner.probe.result.cca.CcaTestResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.tlsscanner.serverscanner.task.CcaTask;
import java.util.LinkedList;
import java.util.List;

public class CcaProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private List<VersionSuiteListPair> versionSuiteListPairsList;

    private static final boolean INCREASING_TIMEOUT = false;

    private static final long ADDITIONAL_TIMEOUT = 10000;

    private static final long ADDITIONAL_TCP_TIMEOUT = 1000;

    private static final int REEXECUTIONS = 3;

    private TestResult vulnerable;
    private List<CcaTestResult> resultList;

    public CcaProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CCA, configSelector);
        versionSuiteListPairsList = new LinkedList<>();
        register(TlsAnalyzedProperty.VULNERABLE_TO_CCA_BYPASS, TlsAnalyzedProperty.LIST_CCA_TESTRESULT);
    }

    @Override
    public void executeTest() {
        ParallelExecutor parallelExecutor = getParallelExecutor();

        CcaDelegate ccaDelegate = configSelector.getScannerConfig().getCcaDelegate();

        CcaCertificateManager ccaCertificateManager = new CcaCertificateManager(ccaDelegate);

        List<ProtocolVersion> desiredVersions = new LinkedList<>();
        desiredVersions.add(ProtocolVersion.TLS11);
        desiredVersions.add(ProtocolVersion.TLS10);
        desiredVersions.add(ProtocolVersion.TLS12);

        List<VersionSuiteListPair> versionSuiteListPairs = getVersionSuitePairList(desiredVersions);

        if (versionSuiteListPairs.isEmpty()) {
            LOGGER.warn("No common cipher suites found. Can't continue scan.");
            vulnerable = TestResults.COULD_NOT_TEST;
            return;
        }

        Boolean haveClientCertificate = ccaDelegate.clientCertificateSupplied();
        Boolean gotDirectoryParameters = ccaDelegate.directoriesSupplied();

        List<TlsTask> taskList = new LinkedList<>();
        List<CcaTaskVectorPair> taskVectorPairList = new LinkedList<>();

        for (CcaWorkflowType ccaWorkflowType : CcaWorkflowType.values()) {
            for (CcaCertificateType ccaCertificateType : CcaCertificateType.values()) {
                /*
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
                        configSelector.repairConfig(tlsConfig);
                        CcaTask ccaTask = new CcaTask(ccaVector, tlsConfig, ccaCertificateManager, ADDITIONAL_TIMEOUT,
                            INCREASING_TIMEOUT, REEXECUTIONS, ADDITIONAL_TCP_TIMEOUT);
                        taskList.add(ccaTask);
                        taskVectorPairList.add(new CcaTaskVectorPair(ccaTask, ccaVector));
                    }
                }
            }
        }

        resultList = new LinkedList<>();
        boolean handshakeSucceeded = false;
        parallelExecutor.bulkExecuteTasks(taskList);
        for (CcaTaskVectorPair ccaTaskVectorPair : taskVectorPairList) {
            if (ccaTaskVectorPair.getCcaTask().isHasError()) {
                LOGGER.warn("Failed to scan " + ccaTaskVectorPair);
            } else {
                boolean vectorVulnerable;
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
        vulnerable = handshakeSucceeded ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    protected Requirement getRequirements() {
        return new ProbeRequirement().requireAnalyzedProperties(TlsAnalyzedProperty.REQUIRES_CCA)
            .requireProbeTypes(TlsProbeType.PROTOCOL_VERSION);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void adjustConfig(ServerReport report) {
        versionSuiteListPairsList.addAll(((ListResult<VersionSuiteListPair>) report.getResultMap()
            .get(TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS.name())).getList());
    }

    private Config generateConfig() {
        Config config = configSelector.getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setAutoSelectCertificate(false);
        config.setClientAuthentication(true);
        return config;
    }

    private List<VersionSuiteListPair> getVersionSuitePairList(List<ProtocolVersion> desiredVersions) {
        List<VersionSuiteListPair> versionSuiteListPairs = new LinkedList<>();
        for (VersionSuiteListPair versionSuiteListPair : versionSuiteListPairsList) {
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
        if (configSelector.getScannerConfig().getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
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

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.VULNERABLE_TO_CCA_BYPASS, vulnerable);
        put(TlsAnalyzedProperty.LIST_CCA_TESTRESULT, resultList);
    }
}
