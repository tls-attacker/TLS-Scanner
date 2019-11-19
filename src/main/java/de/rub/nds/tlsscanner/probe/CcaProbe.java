/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateGenerator;
import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateType;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowGenerator;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.attacks.config.CcaCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
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

import java.util.LinkedList;
import java.util.List;

public class CcaProbe extends TlsProbe {
    private List<VersionSuiteListPair> versionSuiteListPairsList;

    public CcaProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CCA, config, 5);
        versionSuiteListPairsList = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {
        CcaCommandConfig ccaConfig = new CcaCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) ccaConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
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
         * TODO: Do I want to make sure it's the same for all? If yes I'd have the take a DH/DHE suite from the lowest
         * protocol version and use that.
         */
        List<VersionSuiteListPair> _ = new LinkedList<>();
        if (!getScannerConfig().getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            for(VersionSuiteListPair versionSuiteListPair: versionSuiteListPairs) {
                List<CipherSuite> cipherSuites = new LinkedList<>();
                for(CipherSuite cipherSuite: versionSuiteListPair.getCiphersuiteList()) {
                    if (AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isKeyExchangeDh()) {
                        cipherSuites.add(cipherSuite);
                        break;
                    }
                }
                /**
                 * Only add a version if we found a matching cipher suite (DH[E])
                 */
                if (!cipherSuites.isEmpty()) {
                    _.add(new VersionSuiteListPair(versionSuiteListPair.getVersion(), cipherSuites));
                }
            }
        }

        if (!_.isEmpty()) {
            versionSuiteListPairs = _;
        }

        /**
         * TODO: Currently, if no DH/DHE suite is supported in any TLSv1.0-1.2 Version we fall back to a detailed scan
         * Do we really want this?
         * Additionally we do not ensure that at least one cipher suite for any version of TLSv1.0-1.2 is supported.
         * This will lead to problems with servers supporting none of these.
         */

        /**
         * TODO: Currently we only send a single certificate. But we'll need to send the whole chain later on. That
         * won't work with the way we currently specify the client_input. Gotta see how to handle that
         */

        List<CcaTestResult> resultList = new LinkedList<>();
        Boolean bypassable = false;
        for (CcaWorkflowType ccaWorkflowType : CcaWorkflowType.values()) {
            for (CcaCertificateType ccaCertificateType : CcaCertificateType.values()) {
                for (VersionSuiteListPair versionSuiteListPair : versionSuiteListPairs) {
                    for (CipherSuite cipherSuite : versionSuiteListPair.getCiphersuiteList()) {
                        CertificateMessage certificateMessage = null;
                        Config tlsConfig = ccaConfig.createConfig();
                        tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuite);
                        tlsConfig.setHighestProtocolVersion(versionSuiteListPair.getVersion());
                        certificateMessage = CcaCertificateGenerator.generateCertificate(ccaDelegate, ccaCertificateType);
                        WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaWorkflowType,
                                certificateMessage);
                        State state = new State(tlsConfig, trace);
                        try {
                            executeState(state);
                        } catch (Exception E) {
                            LOGGER.error("Error while testing for client authentication bypasses." + E);
                        }
                        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
                            bypassable = true;
                            resultList.add(new CcaTestResult(true, ccaWorkflowType, ccaCertificateType,
                                    versionSuiteListPair.getVersion(), cipherSuite));
                        } else {
                            resultList.add(new CcaTestResult(false, ccaWorkflowType, ccaCertificateType,
                                    versionSuiteListPair.getVersion(), cipherSuite));
                        }
                    }
                }
            }
        }
        return new CcaResult(bypassable ? TestResult.TRUE : TestResult.FALSE, resultList);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if ((report.getResult(AnalyzedProperty.SUPPORTS_CCA) == TestResult.TRUE)
                && (report.getVersionSuitePairs() != null)) {
            return true;
        };
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

}


/**
 * TODO: Note that when using a pem encoded certificate we still got the following results
 * check what this means.
 * Client authentication
 *
 * Supported			 : true
 * CRT_CKE_CCS_FIN.CLIENT_INPUT.TLS10.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CRT_CKE_CCS_FIN.CLIENT_INPUT.TLS11.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CRT_CKE_CCS_FIN.CLIENT_INPUT.TLS12.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CKE_CCS_FIN.CLIENT_INPUT.TLS10.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CKE_CCS_FIN.CLIENT_INPUT.TLS11.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CKE_CCS_FIN.CLIENT_INPUT.TLS12.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CKE_CCS_FIN.EMPTY.TLS10.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CKE_CCS_FIN.EMPTY.TLS11.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CKE_CCS_FIN.EMPTY.TLS12.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CKE_CCS_CRT_FIN_CCS_RND.CLIENT_INPUT.TLS10.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CKE_CCS_CRT_FIN_CCS_RND.CLIENT_INPUT.TLS11.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 * CKE_CCS_CRT_FIN_CCS_RND.CLIENT_INPUT.TLS12.TLS_DHE_RSA_WITH_AES_128_CBC_SHA : true
 */
