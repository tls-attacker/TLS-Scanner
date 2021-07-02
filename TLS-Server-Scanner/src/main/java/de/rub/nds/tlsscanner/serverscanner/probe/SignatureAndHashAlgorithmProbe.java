/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReportGenerator;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.SignatureAndHashAlgorithmResult;
import org.bouncycastle.asn1.x509.Certificate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class SignatureAndHashAlgorithmProbe extends TlsProbe {

    private List<ProtocolVersion> versions;

    public SignatureAndHashAlgorithmProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SIGNATURE_AND_HASH, config);
    }

    @Override
    public ProbeResult executeTest() {
        Set<SignatureAndHashAlgorithm> supported = new HashSet<>();
        TestResult respectsExtension = TestResult.TRUE;
        for (ProtocolVersion version : this.versions) {
            Config tlsConfig = this.getBasicConfig();
            tlsConfig.setHighestProtocolVersion(version);
            tlsConfig.setDefaultClientSupportedCipherSuites(ProtocolVersion.TLS13.equals(version)
                ? CipherSuite.getImplementedTls13CipherSuites() : CipherSuite.getImplemented());

            List<SignatureAndHashAlgorithm> toTestList =
                new ArrayList<>(Arrays.asList(SignatureAndHashAlgorithm.values()));
            toTestList.removeAll(supported);
            State state;

            do {
                state = this.testAlgorithms(toTestList, tlsConfig);
                if (state != null) {
                    Set<SignatureAndHashAlgorithm> selected = getSelectedSignatureAndHashAlgorithms(state);
                    supported.addAll(selected);
                    if (!toTestList.containsAll(selected)) {
                        respectsExtension = TestResult.FALSE;
                        break;
                    }
                    toTestList.removeAll(selected);
                }
            } while (state != null && toTestList.size() > 0);
        }
        return new SignatureAndHashAlgorithmResult(new ArrayList<>(supported), respectsExtension);
    }

    private Set<SignatureAndHashAlgorithm> getSelectedSignatureAndHashAlgorithms(State state) {
        Set<SignatureAndHashAlgorithm> selected = new HashSet<>();
        for (Certificate cert : state.getTlsContext().getServerCertificate().getCertificateList()) {
            SignatureAndHashAlgorithm sigHashAlgo = CertificateReportGenerator.getSignatureAndHashAlgorithm(cert);
            if (sigHashAlgo != null) {
                selected.add(sigHashAlgo);
            }
        }
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, state.getWorkflowTrace())) {
            HandshakeMessage message = WorkflowTraceUtil
                .getLastReceivedMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, state.getWorkflowTrace());
            if (message instanceof ServerKeyExchangeMessage) {
                ServerKeyExchangeMessage msg = (ServerKeyExchangeMessage) message;
                ModifiableByteArray algByte = msg.getSignatureAndHashAlgorithm();
                if (algByte != null) {
                    SignatureAndHashAlgorithm sigHashAlgo =
                        SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(algByte.getValue());
                    if (sigHashAlgo != null) {
                        selected.add(sigHashAlgo);
                    }
                }
            }
        }
        return selected;
    }

    private State testAlgorithms(List<SignatureAndHashAlgorithm> algorithms, Config config) {
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(algorithms);
        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state;
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    private Config getBasicConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);

        return tlsConfig;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        this.versions = report.getVersions();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SignatureAndHashAlgorithmResult(null, TestResult.COULD_NOT_TEST);
    }
}
