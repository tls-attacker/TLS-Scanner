/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateManager;
import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateType;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.attacks.cca.vector.CcaTaskVectorPair;
import de.rub.nds.tlsattacker.attacks.cca.vector.CcaVector;
import de.rub.nds.tlsattacker.attacks.task.CcaTask;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.CcaResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.cca.CcaTestResult;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class CcaProbe extends TlsProbe {
    private List<VersionSuiteListPair> versionSuiteListPairsList;

    private boolean increasingTimeout = false;

    private long additionalTimeout = 1000;

    private long additionalTcpTimeout = 1000;

    public CcaProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CCA, config, 7);
        versionSuiteListPairsList = new LinkedList<>();
    }

    /**
     * TODO: idea empty CKE message (see post robert slack)
     * @return
     */

    @Override
    public ProbeResult executeTest() {

        /**
         * Get the parallel executor
         * Note: the executor is affected by -parallelProbes. If not set the size is 1 (yawn)
         */
        ParallelExecutor parallelExecutor = getParallelExecutor();

        CcaDelegate ccaDelegate = (CcaDelegate) getScannerConfig().getDelegate(CcaDelegate.class);

        /**
         * Add any protocol version (1.0-1.2) to the versions we iterate
         */
        List<ProtocolVersion> desiredVersions = new LinkedList<>();
        desiredVersions.add(ProtocolVersion.TLS11);
        desiredVersions.add(ProtocolVersion.TLS10);
        desiredVersions.add(ProtocolVersion.TLS12);


        /**
         * Add any VersionSuitePair that is supported by the target
         * and by our test cases (Version 1.0 - 1.2)
         */
        List<VersionSuiteListPair> versionSuiteListPairs = new LinkedList<>();
        for(VersionSuiteListPair versionSuiteListPair: this.versionSuiteListPairsList) {
            if (desiredVersions.contains(versionSuiteListPair.getVersion())) {
                versionSuiteListPairs.add(versionSuiteListPair);
            }
        }

        /**
         * If we do not want a detailed scan, use only one cipher suite per protocol version.
         */
        List<CipherSuite> implementedCipherSuites = CipherSuite.getImplemented();
        List<VersionSuiteListPair> versionSuiteListPairList = new LinkedList<>();
        if (!getScannerConfig().getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            for (VersionSuiteListPair versionSuiteListPair: versionSuiteListPairs) {
                List<CipherSuite> cipherSuites = new LinkedList<>();
                for (CipherSuite cipherSuite: versionSuiteListPair.getCiphersuiteList()) {
                    if (AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isKeyExchangeDh() && implementedCipherSuites.contains(cipherSuite)) {
                        cipherSuites.add(cipherSuite);
                        break;
                    }
                }
                /**
                 * Only add a version if we found a matching cipher suite (DH[E])
                 */
                if (!cipherSuites.isEmpty()) {
                    versionSuiteListPairList.add(new VersionSuiteListPair(versionSuiteListPair.getVersion(), cipherSuites));
                }
            }
        }

        if (versionSuiteListPairList.isEmpty()) {
            /**
             * We haven't found a DH ciphersuite that's implemented by TLS-Scanner/Attacker
             * Remove any cipherSuite not implemented by TLS-Scanner/Attacker to prevent confusing results
             */
            for (VersionSuiteListPair versionSuiteListPair : versionSuiteListPairs) {
                List<CipherSuite> cipherSuites = new LinkedList<>();
                for (CipherSuite cipherSuite : versionSuiteListPair.getCiphersuiteList()) {
                    if (implementedCipherSuites.contains(cipherSuite)) {
                        cipherSuites.add(cipherSuite);
                    }
                }
                if (!cipherSuites.isEmpty()) {
                    versionSuiteListPairList.add(new VersionSuiteListPair(versionSuiteListPair.getVersion(), cipherSuites));
                }
            }
        }
        /**
         * versionSuiteListPairs by now contains either any ciphersuite that both the server and TLS-Scanner/Attacker
         * support for TLS1.0-1.2 or at most a single DH ciphersuite per version. If it's empty we can't continue.
         */
        versionSuiteListPairs = versionSuiteListPairList;


        // Changes for Wolfssl
        List<CipherSuite> cipherSuites = new LinkedList<>();
        List<VersionSuiteListPair> _versionSuiteListPairs = new LinkedList<>();

        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);


        _versionSuiteListPairs.add(new VersionSuiteListPair(ProtocolVersion.TLS12, cipherSuites));
//        _versionSuiteListPairs.add(new VersionSuiteListPair(ProtocolVersion.TLS11, cipherSuites));
//        _versionSuiteListPairs.add(new VersionSuiteListPair(ProtocolVersion.TLS10, cipherSuites));
        versionSuiteListPairs = _versionSuiteListPairs;
        // EOF Wolfssl changes


        if (versionSuiteListPairs.isEmpty()) {
            LOGGER.error("No common ciphersuites found. Can't continue scan.");
            return new CcaResult(TestResult.COULD_NOT_TEST, null);
        }

        Boolean haveClientCertificate = ccaDelegate.clientCertificateSupplied();
        Boolean gotDirectoryParameters = ccaDelegate.directoriesSupplied();

        List<TlsTask> taskList = new LinkedList<>();
        List<CcaTaskVectorPair> taskVectorPairList = new LinkedList<>();

        for (CcaWorkflowType ccaWorkflowType : CcaWorkflowType.values()) {
            for (CcaCertificateType ccaCertificateType : CcaCertificateType.values()) {
                /**
                 * Skip certificate types for which we are lacking the corresponding CLI parameters
                 * Additionally skip certificate types that aren't required. I.e. a flow not sending a certificate message
                 * can simply run once with the CcaCertificateType EMPTY
                 */
                if ((ccaCertificateType.getRequiresCertificate() && !haveClientCertificate)
                || (ccaCertificateType.getRequiresCaCertAndKeys() && !gotDirectoryParameters)
                || (!ccaWorkflowType.getRequiresCertificate() && ccaCertificateType != CcaCertificateType.EMPTY)) {
                    continue;
                }
                for (VersionSuiteListPair versionSuiteListPair : versionSuiteListPairs) {
                    for (CipherSuite cipherSuite : versionSuiteListPair.getCiphersuiteList()) {

                        CcaVector ccaVector = new CcaVector(versionSuiteListPair.getVersion(), cipherSuite, ccaWorkflowType, ccaCertificateType);
                        Config tlsConfig = generateConfig();
                        CcaTask ccaTask = new CcaTask(ccaVector, tlsConfig, ccaDelegate, additionalTimeout, increasingTimeout,
                                3, additionalTcpTimeout);
                        taskList.add(ccaTask);
                        taskVectorPairList.add(new CcaTaskVectorPair(ccaTask, ccaVector));
                    }
                }
            }
        }

        List<CcaTestResult> resultList = new LinkedList<>();
        Boolean bypassable = false;
        parallelExecutor.bulkExecuteTasks(taskList);
        for (CcaTaskVectorPair ccaTaskVectorPair : taskVectorPairList) {
            if (ccaTaskVectorPair.getCcaTask().isHasError()) {
                LOGGER.warn("Failed to scan " + ccaTaskVectorPair);
            } else {
                Boolean vectorVulnerable = false;
                if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, ccaTaskVectorPair.getCcaTask()
                        .getState().getWorkflowTrace())) {
                    bypassable = true;
                    vectorVulnerable = true;
                } else {
                    vectorVulnerable = false;
                }
                resultList.add(new CcaTestResult(vectorVulnerable, ccaTaskVectorPair.getVector().getCcaWorkflowType(),
                        ccaTaskVectorPair.getVector().getCcaCertificateType(), ccaTaskVectorPair.getVector().getProtocolVersion(),
                        ccaTaskVectorPair.getVector().getCipherSuite()));
            }
        }

        return new CcaResult(bypassable ? TestResult.TRUE : TestResult.FALSE, resultList);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if ((report.getResult(AnalyzedProperty.REQUIRES_CCA) == TestResult.TRUE)
                && (report.getVersionSuitePairs() != null)) {
            return true;
        };
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
//        this.versionSuiteListPairsList.addAll(report.getVersionSuitePairs());
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CcaResult(TestResult.COULD_NOT_TEST, null);
    }

    private Config generateConfig() {
        Config config = getScannerConfig().createConfig();
        config.setAutoSelectCertificate(false);
        config.setAddServerNameIndicationExtension(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);
        config.setDefaultHighestClientProtocolVersion(ProtocolVersion.TLS10);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setStopTraceAfterUnexpected(true);

        return config;
    }

}