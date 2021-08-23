/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import com.google.common.collect.Sets;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
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
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class SignatureAndHashAlgorithmProbe extends TlsProbe {

    private List<ProtocolVersion> versions;
    private TestResult respectsExtension;

    public SignatureAndHashAlgorithmProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SIGNATURE_AND_HASH, config);
    }

    @Override
    public ProbeResult executeTest() {
        Set<SignatureAndHashAlgorithm> supportedCert = new HashSet<>();
        Set<SignatureAndHashAlgorithm> supportedSke = new HashSet<>();
        this.respectsExtension = TestResult.TRUE;
        for (ProtocolVersion version : this.versions) {
            if (version.isTLS13()) {
                supportedCert.addAll(testForVersion(version, CipherSuite::isTLS13, AlgorithmLocation.CERT));
                supportedSke.addAll(testForVersion(version, CipherSuite::isTLS13, AlgorithmLocation.SKE));
            } else {
                supportedCert.addAll(testForVersion(version, suite -> !suite.isTLS13(), AlgorithmLocation.CERT));
                supportedSke.addAll(testForVersion(version, suite -> !suite.isTLS13(), AlgorithmLocation.SKE));
                supportedSke.addAll(
                    testForVersion(version, suite -> !suite.isTLS13() && suite.isEphemeral(), AlgorithmLocation.SKE));
            }
        }
        return new SignatureAndHashAlgorithmResult(new ArrayList<>(supportedCert), new ArrayList<>(supportedSke),
            respectsExtension);
    }

    private Set<SignatureAndHashAlgorithm> testForVersion(ProtocolVersion version, Predicate<CipherSuite> predicate,
        AlgorithmLocation location) {
        Set<SignatureAndHashAlgorithm> found = new HashSet<>();
        Set<List<SignatureAndHashAlgorithm>> tested = new HashSet<>();

        Config tlsConfig = version.isTLS13() ? getTls13Config() : this.getBasicConfig();
        tlsConfig.setHighestProtocolVersion(version);
        tlsConfig.getDefaultClientSupportedCipherSuites().removeIf(predicate.negate());

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
                Set<SignatureAndHashAlgorithm> selected = location.extract(state);
                if (!testSet.containsAll(selected) && (!version.isTLS13() || location.isStrict())) {
                    found.addAll(selected);
                    respectsExtension = TestResult.FALSE;
                    break;
                }
                // if any new algorithms were found
                if (selected.stream().anyMatch(algorithm -> !found.contains(algorithm))) {
                    // move selected to end
                    List<SignatureAndHashAlgorithm> selectedContained =
                        selected.stream().filter(selected::contains).collect(Collectors.toList());
                    if (selectedContained.size() > 0) {
                        List<SignatureAndHashAlgorithm> selectedToEnd = new ArrayList<>(testSet);
                        selectedToEnd.removeAll(selectedContained);
                        selectedToEnd.addAll(selectedContained);
                        testQueue.add(selectedToEnd);
                    }
                    // remove possible combinations of selected
                    for (Set<SignatureAndHashAlgorithm> subSet : Sets.powerSet(selected)) {
                        if (subSet.isEmpty()) {
                            continue;
                        }
                        List<SignatureAndHashAlgorithm> newTestSet = new ArrayList<>(testSet);
                        newTestSet.removeAll(subSet);
                        testQueue.add(newTestSet);
                    }
                }
                found.addAll(selected);
            }
        }
        return found;
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

    private Config getBasicConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getImplemented());

        return tlsConfig;
    }

    private Config getTls13Config() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getImplementedTls13CipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.values());
        tlsConfig.setDefaultClientKeyShareNamedGroups(NamedGroup.values());
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        return tlsConfig;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)
            && (report.getVersions().contains(ProtocolVersion.TLS12)
                || report.getVersions().contains(ProtocolVersion.TLS13));
    }

    @Override
    public void adjustConfig(SiteReport report) {
        this.versions = new ArrayList<>(report.getVersions());
        this.versions.removeIf(version -> version.compare(ProtocolVersion.TLS12) < 0);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SignatureAndHashAlgorithmResult(null, null, TestResult.COULD_NOT_TEST);
    }

    private enum AlgorithmLocation {

        CERT(AlgorithmLocation::getSelectedSignatureAndHashAlgorithmsCert, false),
        SKE(AlgorithmLocation::getSelectedSignatureAndHashAlgorithmsSke, true);

        private final Function<State, Set<SignatureAndHashAlgorithm>> extractor;
        private final boolean strict;

        AlgorithmLocation(Function<State, Set<SignatureAndHashAlgorithm>> extractor, boolean strict) {
            this.extractor = extractor;
            this.strict = strict;
        }

        public Set<SignatureAndHashAlgorithm> extract(State state) {
            return this.extractor.apply(state);
        }

        public boolean isStrict() {
            return strict;
        }

        private static Set<SignatureAndHashAlgorithm> getSelectedSignatureAndHashAlgorithmsCert(State state) {
            Set<SignatureAndHashAlgorithm> selected = new HashSet<>();
            org.bouncycastle.crypto.tls.Certificate certificate = state.getTlsContext().getServerCertificate();
            if (certificate != null && certificate.getCertificateList() != null) {
                for (Certificate cert : certificate.getCertificateList()) {
                    SignatureAndHashAlgorithm sigHashAlgo =
                        CertificateReportGenerator.getSignatureAndHashAlgorithm(cert);
                    if (sigHashAlgo != null) {
                        selected.add(sigHashAlgo);
                    }
                }
            }
            return selected;
        }

        private static Set<SignatureAndHashAlgorithm> getSelectedSignatureAndHashAlgorithmsSke(State state) {
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE,
                state.getWorkflowTrace())) {
                HandshakeMessage message = WorkflowTraceUtil
                    .getLastReceivedMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, state.getWorkflowTrace());
                if (message instanceof ServerKeyExchangeMessage) {
                    ServerKeyExchangeMessage msg = (ServerKeyExchangeMessage) message;
                    ModifiableByteArray algByte = msg.getSignatureAndHashAlgorithm();
                    if (algByte != null) {
                        SignatureAndHashAlgorithm sigHashAlgo =
                            SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(algByte.getValue());
                        if (sigHashAlgo != null) {
                            return Collections.singleton(sigHashAlgo);
                        }
                    }
                }
            }
            return Collections.emptySet();
        }
    }
}
