/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.TlsClientConfig;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClientResult;
import static de.rub.nds.tlsscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.ConfigFileList;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulationRequest;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.HandshakeSimulationResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class HandshakeSimulationProbe extends TlsProbe {

    private static final String RESOURCE_FOLDER = "/extracted_client_configs";

    private final List<SimulationRequest> simmulationRequestList;

    public HandshakeSimulationProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HANDSHAKE_SIMULATION, config, 1);
        simmulationRequestList = new LinkedList<>();
        ConfigFileList configFileList = ConfigFileList.loadConfigFileList("/" + ConfigFileList.FILE_NAME);
        for (String configFileName : configFileList.getFiles()) {
            try {
                TlsClientConfig tlsClientConfig = TlsClientConfig.createTlsClientConfig(RESOURCE_FOLDER + "/" + configFileName);
                if (getScannerConfig().getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                    simmulationRequestList.add(new SimulationRequest(tlsClientConfig));
                } else {
                    simmulationRequestList.add(new SimulationRequest(tlsClientConfig));
                }
            } catch (Exception E) {
                LOGGER.error("Could not load " + configFileName, E);
            }
        }
    }

    @Override
    public ProbeResult executeTest() {
        List<State> clientStateList = new LinkedList<>();
        List<SimulatedClientResult> resultList = new LinkedList<>();
        for (SimulationRequest request : simmulationRequestList) {
            State state = request.getExecutableState(scannerConfig);
            clientStateList.add(state);
            resultList.add(new SimulatedClientResult(request.getTlsClientConfig(), state));
        }
        executeState(clientStateList);
        for (SimulatedClientResult result : resultList) {
            evaluateClientConfig(result);
            evaluateReceivedMessages(result);
        }
        return new HandshakeSimulationResult(resultList);
    }

    private void evaluateClientConfig(SimulatedClientResult simulatedClient) {
        Config config = simulatedClient.getState().getConfig();
        simulatedClient.setHighestClientProtocolVersion(config.getHighestProtocolVersion());
        simulatedClient.setClientSupportedCiphersuites(config.getDefaultClientSupportedCiphersuites());
        if (config.isAddAlpnExtension()) {
            simulatedClient.setAlpnAnnouncedProtocols(Arrays.toString(config.getAlpnAnnouncedProtocols()));
        } else {
            simulatedClient.setAlpnAnnouncedProtocols("-");
        }
        simulatedClient.setSupportedVersionList(simulatedClient.getTlsClientConfig().getSupportedVersionList());
        simulatedClient.setVersionAcceptForbiddenCiphersuiteList(simulatedClient.getTlsClientConfig().getVersionAcceptForbiddenCiphersuiteList());
        simulatedClient.setSupportedRsaKeySizeList(simulatedClient.getTlsClientConfig().getSupportedRsaKeySizeList());
        simulatedClient.setSupportedDheKeySizeList(simulatedClient.getTlsClientConfig().getSupportedDheKeySizeList());
    }

    private void evaluateReceivedMessages(SimulatedClientResult simulatedClient) {
        WorkflowTrace trace = simulatedClient.getState().getWorkflowTrace();
        simulatedClient.setReceivedServerHello(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        simulatedClient.setReceivedCertificate(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, trace));
        simulatedClient.setReceivedServerKeyExchange(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, trace));
        simulatedClient.setReceivedCertificateRequest(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_REQUEST, trace));
        simulatedClient.setReceivedServerHelloDone(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace));
        simulatedClient.setReceivedAlert(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        simulatedClient.setReceivedUnknown(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.UNKNOWN, trace));
        if (!simulatedClient.getReceivedAlert()) {
            boolean receivedAllMandatoryMessages = true;
            if (!simulatedClient.getReceivedServerHello()) {
                receivedAllMandatoryMessages = false;
            }
            if (!simulatedClient.getReceivedCertificate()) {
                receivedAllMandatoryMessages = false;
            }
            if (simulatedClient.getKeyExchangeAlgorithm() != null) {
                switch (simulatedClient.getKeyExchangeAlgorithm()) {
                    case DHE_DSS:
                    case DHE_RSA:
                    case DH_ANON:
                    case ECDHE_ECDSA:
                    case ECDHE_RSA:
                    case ECDH_ANON:
                        if (!simulatedClient.getReceivedServerKeyExchange()) {
                            receivedAllMandatoryMessages = false;
                        }
                        break;
                    default:
                        break;
                }
            }
            if (!simulatedClient.getReceivedServerHelloDone()) {
                receivedAllMandatoryMessages = false;
            }
            simulatedClient.setReceivedAllMandatoryMessages(receivedAllMandatoryMessages);
            if (receivedAllMandatoryMessages) {
                TlsContext context = simulatedClient.getState().getTlsContext();
                evaluateServerHello(context, simulatedClient);
                evaluateCertificate(context, simulatedClient);
                if (simulatedClient.getReceivedServerKeyExchange()) {
                    evaluateServerKeyExchange(context, simulatedClient);
                }
            }
        }
    }

    private void evaluateServerHello(TlsContext context, SimulatedClientResult simulatedClient) {
        simulatedClient.setSelectedProtocolVersion(context.getSelectedProtocolVersion());
        CipherSuite cipherSuite = context.getSelectedCipherSuite();
        simulatedClient.setSelectedCiphersuite(cipherSuite);
        if (cipherSuite.isEphemeral()) {
            simulatedClient.setForwardSecrecy(true);
        } else {
            simulatedClient.setForwardSecrecy(false);
        }
        simulatedClient.setKeyExchangeAlgorithm(AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite));
        simulatedClient.setSelectedCompressionMethod(context.getSelectedCompressionMethod());
        if (context.getNegotiatedExtensionSet() != null) {
            if (!context.getNegotiatedExtensionSet().isEmpty()) {
                simulatedClient.setNegotiatedExtensions(context.getNegotiatedExtensionSet().toString());
            } else {
                simulatedClient.setNegotiatedExtensions("-");
            }
        }
    }

    private void evaluateCertificate(TlsContext context, SimulatedClientResult simulatedClient) {
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa()) {
            simulatedClient.setServerPublicKeyParameter(getRsaPublicKeyFromCert(context.getServerCertificate()));
        }
    }

    private void evaluateServerKeyExchange(TlsContext context, SimulatedClientResult simulatedClient) {
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeDh() && context.getServerDhPublicKey() != null) {
            simulatedClient.setServerPublicKeyParameter(context.getServerDhModulus().bitLength());
        } else if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeEcdh()) {
            if (context.getSelectedGroup() != null) {
                simulatedClient.setSelectedNamedGroup(context.getSelectedGroup().name());
                if (context.getSelectedGroup().getCoordinateSizeInBit() != null) {
                    simulatedClient.setServerPublicKeyParameter(context.getSelectedGroup().getCoordinateSizeInBit());
                }
            }
            if (simulatedClient.getServerPublicKeyParameter() == null) {
                if (context.getServerEcPublicKey() != null) {
                    simulatedClient.setServerPublicKeyParameter(context.getServerEcPublicKey().getX().getData().bitLength() * 8);
                }
            }
        }
    }

    private Integer getRsaPublicKeyFromCert(Certificate certs) {
        try {
            if (certs != null) {
                for (org.bouncycastle.asn1.x509.Certificate cert : certs.getCertificateList()) {
                    X509Certificate x509Cert = new X509CertificateObject(cert);
                    if (x509Cert.getPublicKey() != null) {
                        RSAPublicKey rsaPk = (RSAPublicKey) x509Cert.getPublicKey();
                        return rsaPk.getModulus().bitLength();
                    }
                }
            }
        } catch (CertificateParsingException ex) {
            LOGGER.warn("Could not parse public key from certificate", ex);
        }
        return null;
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return null;
    }
}
