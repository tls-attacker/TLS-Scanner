/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeConnectionTimeoutAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class DtlsHelloVerifyRequestProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private TestResult hasHvrRetransmissions;
    private TestResult checksCookie;
    private TestResult usesVersionInCookie;
    private TestResult usesRandomInCookie;
    private TestResult usesSessionIdInCookie;
    private TestResult usesCiphersuitesInCookie;
    private TestResult usesCompressionsInCookie;

    private Integer cookieLength;

    public DtlsHelloVerifyRequestProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_HELLO_VERIFY_REQUEST, scannerConfig);
        super.register(TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS);
        super.register(TlsAnalyzedProperty.HAS_COOKIE_CHECKS);
        super.register(TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE);
        super.register(TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE);
        super.register(TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE);
        super.register(TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE);
        super.register(TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE);
    }

    @Override
    public void executeTest() {
        try {
            this.hasHvrRetransmissions = hasHvrRetransmissions();
            this.checksCookie = checksCookie();
            this.usesVersionInCookie = usesVersionInCookie();
            this.usesRandomInCookie = usesRandomInCookie();
            this.usesSessionIdInCookie = usesSessionIdInCookie();
            this.usesCiphersuitesInCookie = usesCiphersuitesInCookie();
            this.usesCompressionsInCookie = usesCompressionsInCookie();
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            this.hasHvrRetransmissions =
                this.checksCookie = this.usesVersionInCookie = this.usesRandomInCookie = this.usesSessionIdInCookie =
                    this.usesCiphersuitesInCookie = this.usesCompressionsInCookie = TestResults.COULD_NOT_TEST;
            this.cookieLength = -1;
        }
    }

    private TestResult hasHvrRetransmissions() {
        Config config = getConfig();
        config.setAddRetransmissionsToWorkflowTraceInDtls(true);
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ChangeConnectionTimeoutAction(3000));
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        executeState(state);
        HandshakeMessage message = WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.HELLO_VERIFY_REQUEST,
            state.getWorkflowTrace());
        if (message != null) {
            if (message.isRetransmission()) {
                return TestResults.TRUE;
            } else {
                return TestResults.FALSE;
            }
        } else {
            return TestResults.CANNOT_BE_TESTED;
        }
    }

    private TestResult checksCookie() {
        Config config = getConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            if (state.getTlsContext().getDtlsCookie() != null) {
                cookieLength = state.getTlsContext().getDtlsCookie().length;
                if (cookieLength == 0) {
                    return TestResults.CANNOT_BE_TESTED;
                }
            }
        } else {
            return TestResults.ERROR_DURING_TEST;
        }
        config = getConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        byte[] cookie = new byte[cookieLength];
        Arrays.fill(cookie, (byte) 255);
        clientHelloMessage.setCookie(Modifiable.xor(cookie, 0));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesVersionInCookie() {
        Config config = getConfig();
        config.setHighestProtocolVersion(ProtocolVersion.DTLS10);
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setProtocolVersion(Modifiable.explicit(ProtocolVersion.DTLS12.getValue()));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesRandomInCookie() {
        Config config = getConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        byte[] random = new byte[HandshakeByteLength.RANDOM];
        Arrays.fill(random, (byte) 255);
        clientHelloMessage.setRandom(Modifiable.xor(random, 0));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesSessionIdInCookie() {
        Config config = getConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setSessionId(Modifiable.explicit(ArrayConverter.hexStringToByteArray("FFFF")));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesCiphersuitesInCookie() {
        Config config = getConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setCipherSuites(Modifiable.insert(ArrayConverter.hexStringToByteArray("FFFF"), 0));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesCompressionsInCookie() {
        Config config = getConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setCompressions(Modifiable.insert(ArrayConverter.hexStringToByteArray("FF"), 0));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult getResult(State state) {
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.HELLO_VERIFY_REQUEST, state.getWorkflowTrace())) {
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
                return TestResults.FALSE;
            } else {
                return TestResults.TRUE;
            }
        } else {
            return TestResults.CANNOT_BE_TESTED;
        }
    }

    private Config getConfig() {
        Config config = getScannerConfig().createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        List<CipherSuite> ciphersuites = new LinkedList<>();
        ciphersuites.addAll(Arrays.asList(CipherSuite.values()));
        ciphersuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        ciphersuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setDefaultClientSupportedCipherSuites(ciphersuites);
        List<CompressionMethod> compressionList = new ArrayList<>(Arrays.asList(CompressionMethod.values()));
        config.setDefaultClientSupportedCompressionMethods(compressionList);
        config.setEnforceSettings(false);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        return config;
    }

    @Override
    public DtlsHelloVerifyRequestProbe getCouldNotExecuteResult() {
        this.hasHvrRetransmissions =
            this.checksCookie = this.usesVersionInCookie = this.usesRandomInCookie = this.usesSessionIdInCookie =
                this.usesCiphersuitesInCookie = this.usesCompressionsInCookie = TestResults.COULD_NOT_TEST;
        this.cookieLength = -1;
        return this;
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return ProbeRequirement.NO_REQUIREMENT;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.put(TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS, this.hasHvrRetransmissions);
        super.put(TlsAnalyzedProperty.HAS_COOKIE_CHECKS, this.checksCookie);
        super.put(TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE, this.usesVersionInCookie);
        super.put(TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE, this.usesRandomInCookie);
        super.put(TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE, this.usesSessionIdInCookie);
        super.put(TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE, this.usesCiphersuitesInCookie);
        super.put(TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE, this.usesCompressionsInCookie);
        report.setCookieLength(this.cookieLength);
    }
}
