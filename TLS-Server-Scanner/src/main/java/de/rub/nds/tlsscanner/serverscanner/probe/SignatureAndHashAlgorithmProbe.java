/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.SignatureAndHashAlgorithmResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.function.Predicate;

public class SignatureAndHashAlgorithmProbe extends TlsProbe {

    private List<ProtocolVersion> versions;
    private TestResult respectsExtension;

    public SignatureAndHashAlgorithmProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SIGNATURE_AND_HASH, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        Set<SignatureAndHashAlgorithm> supportedSke = new HashSet<>();
        Set<SignatureAndHashAlgorithm> supportedTls13 = new HashSet<>();
        this.respectsExtension = TestResult.TRUE;
        for (ProtocolVersion version : this.versions) {
            if (version.isTLS13()) {
                supportedTls13.addAll(testForVersion(version, CipherSuite::isTLS13));
            } else {
                supportedSke.addAll(testForVersion(version, suite -> !suite.isTLS13() && suite.isEphemeral()));
            }
        }
        return new SignatureAndHashAlgorithmResult(new ArrayList<>(supportedSke), new ArrayList<>(supportedTls13),
            respectsExtension);
    }

    private Set<SignatureAndHashAlgorithm> testForVersion(ProtocolVersion version, Predicate<CipherSuite> predicate) {
        Set<SignatureAndHashAlgorithm> found = new HashSet<>();
        Set<List<SignatureAndHashAlgorithm>> tested = new HashSet<>();

        Config tlsConfig =
            version.isTLS13() ? getConfigSelector().getTls13BaseConfig() : getConfigSelector().getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setHighestProtocolVersion(version);
        tlsConfig.getDefaultClientSupportedCipherSuites().removeIf(predicate.negate());
        getConfigSelector().repairConfig(tlsConfig);

        Queue<List<SignatureAndHashAlgorithm>> testQueue = new LinkedList<>();
        testQueue.add(version.isTLS13() ? SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms()
            : Arrays.asList(SignatureAndHashAlgorithm.values()));

        State state;

        while (!testQueue.isEmpty()) {
            List<SignatureAndHashAlgorithm> testSet = testQueue.poll();
            if (tested.contains(testSet)) {
                continue;
            }
            tested.add(testSet);

            state = testAlgorithms(testSet, tlsConfig);
            if (state != null) {
                SignatureAndHashAlgorithm selected = version.isTLS13() ? getSelectedSignatureAndHashAlgorithmCV(state)
                    : getSelectedSignatureAndHashAlgorithmSke(state);
                if (selected == null) {
                    continue;
                }
                if (!testSet.contains(selected)) {
                    found.add(selected);
                    respectsExtension = TestResult.FALSE;
                    break;
                }
                // if any new algorithms were found
                if (!found.contains(selected)) {
                    // move selected to end
                    if (testSet.contains(selected)) {
                        List<SignatureAndHashAlgorithm> selectedToEnd = new ArrayList<>(testSet);
                        selectedToEnd.remove(selected);
                        selectedToEnd.add(selected);
                        testQueue.add(selectedToEnd);
                    }
                    // remove possible combinations of selected
                    List<SignatureAndHashAlgorithm> newTestSet = new ArrayList<>(testSet);
                    newTestSet.remove(selected);
                    testQueue.add(newTestSet);
                }
                found.add(selected);
            }
        }
        return found;
    }

    private SignatureAndHashAlgorithm getSelectedSignatureAndHashAlgorithmCV(State state) {
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_VERIFY, state.getWorkflowTrace())) {
            HandshakeMessage message = WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.CERTIFICATE_VERIFY,
                state.getWorkflowTrace());
            if (message instanceof CertificateVerifyMessage) {
                CertificateVerifyMessage msg = (CertificateVerifyMessage) message;
                ModifiableByteArray algByte = msg.getSignatureHashAlgorithm();
                if (algByte != null) {
                    return SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(algByte.getValue());
                }
            }
        }
        return null;
    }

    private SignatureAndHashAlgorithm getSelectedSignatureAndHashAlgorithmSke(State state) {
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, state.getWorkflowTrace())) {
            HandshakeMessage message = WorkflowTraceUtil
                .getLastReceivedMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, state.getWorkflowTrace());
            if (message instanceof ServerKeyExchangeMessage) {
                ServerKeyExchangeMessage msg = (ServerKeyExchangeMessage) message;
                ModifiableByteArray algByte = msg.getSignatureAndHashAlgorithm();
                if (algByte != null) {
                    return SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(algByte.getValue());
                }
            }
        }
        return null;
    }

    private State testAlgorithms(List<SignatureAndHashAlgorithm> algorithms, Config config) {
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(algorithms);
        State state = new State(config);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return state;
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)
            && (report.getVersions().contains(ProtocolVersion.TLS12)
                || report.getVersions().contains(ProtocolVersion.TLS13)
                || report.getVersions().contains(ProtocolVersion.DTLS12));
    }

    @Override
    public void adjustConfig(SiteReport report) {
        this.versions = new ArrayList<>();
        for (ProtocolVersion version : report.getVersions()) {
            if (version.equals(ProtocolVersion.DTLS12) || version.equals(ProtocolVersion.TLS12) || version.isTLS13()) {
                versions.add(version);
            }
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SignatureAndHashAlgorithmResult(null, null, TestResult.COULD_NOT_TEST);
    }
}
