/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.ConfigFileList;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulationRequest;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.TlsClientConfig;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class HandshakeSimulationProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private static final String RESOURCE_FOLDER = "/extracted_client_configs";

    private final List<SimulationRequest> simulationRequestList;
    private List<SimulatedClientResult> simulatedClientList;

    public HandshakeSimulationProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HANDSHAKE_SIMULATION, configSelector);
        register(TlsAnalyzedProperty.CLIENT_SIMULATION_RESULTS);

        simulationRequestList = new LinkedList<>();
        ConfigFileList configFileList = ConfigFileList.loadConfigFileList("/" + ConfigFileList.FILE_NAME);
        for (String configFileName : configFileList.getFiles()) {
            try {
                TlsClientConfig tlsClientConfig =
                    TlsClientConfig.createTlsClientConfig(RESOURCE_FOLDER + "/" + configFileName);
                if (configSelector.getScannerConfig().getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                    simulationRequestList.add(new SimulationRequest(tlsClientConfig));
                } else {
                    simulationRequestList.add(new SimulationRequest(tlsClientConfig));
                }
            } catch (Exception e) {
                if (e.getCause() instanceof InterruptedException) {
                    LOGGER.error("Timeout on " + getProbeName());
                    throw new RuntimeException(e);
                } else {
                    LOGGER.error("Could not load " + configFileName, e);
                }
            }
        }
    }

    @Override
    public void executeTest() {
        List<State> clientStateList = new LinkedList<>();
        simulatedClientList = new LinkedList<>();
        for (SimulationRequest request : simulationRequestList) {
            State state = request.getExecutableState(configSelector.getScannerConfig());
            clientStateList.add(state);
        }
        executeState(clientStateList);
        for (SimulatedClientResult result : simulatedClientList) {
            // evaluateClientConfig(result);
            // evaluateReceivedMessages(result);
        }
    }

    private void evaluateClientConfig(SimulatedClientResult simulatedClient, State state) {
        Config config = state.getConfig();
        config.setStopActionsAfterIOException(true);
        simulatedClient.setHighestClientProtocolVersion(config.getHighestProtocolVersion());
        simulatedClient.setClientSupportedCipherSuites(config.getDefaultClientSupportedCipherSuites());
        if (config.isAddAlpnExtension()) {
            simulatedClient.setAlpnAnnouncedProtocols(config.getDefaultProposedAlpnProtocols());
        } else {
            simulatedClient.setAlpnAnnouncedProtocols(new LinkedList<>());
        }
        simulatedClient.setSupportedVersionList(simulatedClient.getTlsClientConfig().getSupportedVersionList());
        simulatedClient.setVersionAcceptForbiddenCipherSuiteList(
            simulatedClient.getTlsClientConfig().getVersionAcceptForbiddenCipherSuiteList());
        simulatedClient.setSupportedRsaKeySizeList(simulatedClient.getTlsClientConfig().getSupportedRsaKeySizeList());
        simulatedClient.setSupportedDheKeySizeList(simulatedClient.getTlsClientConfig().getSupportedDheKeySizeList());
    }

    private void evaluateReceivedMessages(SimulatedClientResult simulatedClient, State state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        simulatedClient
            .setReceivedServerHello(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        simulatedClient
            .setReceivedCertificate(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, trace));
        simulatedClient.setReceivedServerKeyExchange(
            WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, trace));
        simulatedClient.setReceivedCertificateRequest(
            WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_REQUEST, trace));
        simulatedClient.setReceivedServerHelloDone(
            WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace));
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
                TlsContext context = state.getTlsContext();
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
        simulatedClient.setSelectedCipherSuite(cipherSuite);
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
                    simulatedClient.setServerPublicKeyParameter(
                        context.getServerEcPublicKey().getFieldX().getData().bitLength() * 8);
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
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.CLIENT_SIMULATION_RESULTS, simulatedClientList);
    }

    @Override
    protected Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }
}
