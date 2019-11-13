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
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
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
import de.rub.nds.tlsscanner.report.result.cca.CcaTestResult;

import java.util.LinkedList;
import java.util.List;

public class CcaProbe extends TlsProbe {
    private List<CipherSuite> suiteList;
    private List<ProtocolVersion> versions;

    public CcaProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CCA, config, 5);
        suiteList = new LinkedList<>();
        versions = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {
        CcaCommandConfig ccaConfig = new CcaCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) ccaConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        CcaDelegate ccaDelegate = (CcaDelegate) getScannerConfig().getDelegate(CcaDelegate.class);

        /**
         * Select the cipher suites to be used during testing
         */
        List<CipherSuite> cipherSuites = new LinkedList<>();
        if (getScannerConfig().getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {

            cipherSuites.addAll(this.suiteList);
            cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
            cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        } else {
            for(CipherSuite cipherSuite : this.suiteList) {
                if (AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.DHE_RSA
                || AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.DHE_DSS) {
                    cipherSuites.add(cipherSuite);
                    break;
                }
            }
            /**
             * We couldn't find a DHE cipher suite.
             * Let's try out luck with a DH cipher suite.
             */
            if (cipherSuites.isEmpty()) {
                for(CipherSuite cipherSuite : this.suiteList) {
                    if (AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.DH_RSA
                            || AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.DH_DSS) {
                        cipherSuites.add(cipherSuite);
                        break;
                    }
                }
            }
            /**
             * Still no luck finding a matching cipher suite, we'll throw an error for now.
             */
            if (cipherSuites.isEmpty()) {
                LOGGER.error("Couldn't find any cipher suite to execute all tests. " +
                        "Consider scanning again with -scanDetail DETAILED.");
                return new CcaResult(TestResult.COULD_NOT_TEST, null);
            }
        }

        /**
         * Add any protocol version (1.0-1.2) to the versions we iterate
         */
        List<ProtocolVersion> protocolVersions = new LinkedList<>();
        List<ProtocolVersion> desiredVersions = new LinkedList<>();
        desiredVersions.add(ProtocolVersion.TLS10);
        desiredVersions.add(ProtocolVersion.TLS11);
        desiredVersions.add(ProtocolVersion.TLS12);

        for(ProtocolVersion protocolVersion : this.versions) {
            if (desiredVersions.contains(protocolVersion)) {
                protocolVersions.add(protocolVersion);
            }
        }

        List<CcaTestResult> resultList = new LinkedList<>();
        Boolean bypassable = false;
        for (CcaWorkflowType ccaWorkflowType : CcaWorkflowType.values()) {
            for (CcaCertificateType ccaCertificateType : CcaCertificateType.values()) {
                for (ProtocolVersion protocolVersion : protocolVersions) {
                    for (CipherSuite cipherSuite : cipherSuites) {
                        CertificateMessage certificateMessage = null;
                        Config tlsConfig = ccaConfig.createConfig();
                        tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuite);
                        tlsConfig.setHighestProtocolVersion(protocolVersion);
                        certificateMessage = CcaCertificateGenerator.generateCertificate(ccaDelegate, ccaConfig, ccaCertificateType);
                        WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaWorkflowType,
                                certificateMessage);
                        State state = new State(tlsConfig, trace);
                        try {
                            executeState(state);
                        } catch (Exception E) {
                            LOGGER.error("Error while testing for client authentication bypasses.");
                        }
                        // TODO: implement check for reponse of unkown cipher suite. It's just confusing in the results.
                        // I'm unsure how to exactly do that since I doubt all implementations will just tell me they
                        // don't know the ciphersuite. Maybe I can find a way around that. 
                        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
                            bypassable = true;
                            resultList.add(new CcaTestResult(true, ccaWorkflowType, ccaCertificateType,
                                    protocolVersion, cipherSuite));
                        } else {
                            resultList.add(new CcaTestResult(false, ccaWorkflowType, ccaCertificateType,
                                protocolVersion, cipherSuite));
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
                && (report.getCipherSuites() != null)
                && (report.getVersions() != null)
                && ((report.getVersions().contains(ProtocolVersion.TLS12)
                    || report.getVersions().contains(ProtocolVersion.TLS11)
                    || (report.getVersions().contains(ProtocolVersion.TLS10)))
                    )
        ) {
            return true;
        };
        return false;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        this.suiteList.addAll(report.getCipherSuites());
        this.versions.addAll(report.getVersions());
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CcaResult(TestResult.COULD_NOT_TEST, null);
    }

}
