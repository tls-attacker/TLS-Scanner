/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeConnectionTimeoutAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TightReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;

public class DtlsHelloVerifyRequestProbe extends TlsServerProbe {

    public static Integer COOKIE_LENGTH_ERROR_VALUE = -1;

    private TestResult supportsCookieExchange = TestResults.COULD_NOT_TEST;
    private TestResult hasHvrRetransmissions = TestResults.COULD_NOT_TEST;
    private TestResult checksCookie = TestResults.COULD_NOT_TEST;
    private TestResult usesPortInCookie = TestResults.COULD_NOT_TEST;
    private TestResult usesVersionInCookie = TestResults.COULD_NOT_TEST;
    private TestResult usesRandomInCookie = TestResults.COULD_NOT_TEST;
    private TestResult usesSessionIdInCookie = TestResults.COULD_NOT_TEST;
    private TestResult usesCiphersuitesInCookie = TestResults.COULD_NOT_TEST;
    private TestResult usesCompressionsInCookie = TestResults.COULD_NOT_TEST;

    private Integer cookieLength = COOKIE_LENGTH_ERROR_VALUE;

    public DtlsHelloVerifyRequestProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_HELLO_VERIFY_REQUEST, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE,
                TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS,
                TlsAnalyzedProperty.HAS_COOKIE_CHECKS,
                TlsAnalyzedProperty.USES_PORT_FOR_COOKIE,
                TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE,
                TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE,
                TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE,
                TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE,
                TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE,
                TlsAnalyzedProperty.COOKIE_LENGTH);
    }

    @Override
    protected void executeTest() {
        try {
            supportsCookieExchange = supportsCookieExchange();
            if (supportsCookieExchange == TestResults.TRUE) {
                hasHvrRetransmissions = hasHvrRetransmissions();
                checksCookie = checksCookie();
                usesPortInCookie = usesPortInCookie();
                usesVersionInCookie = usesVersionInCookie();
                usesRandomInCookie = usesRandomInCookie();
                usesSessionIdInCookie = usesSessionIdInCookie();
                usesCiphersuitesInCookie = usesCiphersuitesInCookie();
                usesCompressionsInCookie = usesCompressionsInCookie();
            }
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
        }
    }

    private TestResult supportsCookieExchange() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new TightReceiveAction(new ServerHelloMessage()));
        State state = new State(config, trace);
        executeState(state);
        if (trace.executedAsPlanned()) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }

    private TestResult hasHvrRetransmissions() {
        Config config = configSelector.getBaseConfig();
        config.setAddRetransmissionsToWorkflowTraceInDtls(true);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ChangeConnectionTimeoutAction(3000));
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        executeState(state);
        HandshakeMessage message =
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        state.getWorkflowTrace(), HandshakeMessageType.HELLO_VERIFY_REQUEST);
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
        Config config = configSelector.getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        State state = new State(config);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            if (state.getTlsContext().getDtlsCookie() != null) {
                cookieLength = state.getTlsContext().getDtlsCookie().length;
                if (cookieLength == 0) {
                    return TestResults.CANNOT_BE_TESTED;
                }
            }
        } else {
            return TestResults.ERROR_DURING_TEST;
        }
        config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        byte[] cookie = new byte[cookieLength];
        Arrays.fill(cookie, (byte) 255);
        clientHelloMessage.setCookie(Modifiable.xor(cookie, 0));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesPortInCookie() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ResetConnectionAction(false));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesVersionInCookie() {
        Config config = configSelector.getBaseConfig();
        config.setHighestProtocolVersion(ProtocolVersion.DTLS10);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setProtocolVersion(
                Modifiable.explicit(ProtocolVersion.DTLS12.getValue()));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesRandomInCookie() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        byte[] random = new byte[HandshakeByteLength.RANDOM];
        Arrays.fill(random, (byte) 255);
        clientHelloMessage.setRandom(Modifiable.xor(random, 0));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesSessionIdInCookie() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setSessionId(
                Modifiable.explicit(ArrayConverter.hexStringToByteArray("FFFF")));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesCiphersuitesInCookie() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setCipherSuites(
                Modifiable.insert(ArrayConverter.hexStringToByteArray("FFFF"), 0));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult usesCompressionsInCookie() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setCompressions(
                Modifiable.insert(ArrayConverter.hexStringToByteArray("FF"), 0));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult getResult(State state) {
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.HELLO_VERIFY_REQUEST)) {
            if (WorkflowTraceResultUtil.didReceiveMessage(
                    state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
                return TestResults.FALSE;
            } else {
                return TestResults.TRUE;
            }
        } else {
            return TestResults.CANNOT_BE_TESTED;
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS);
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS, hasHvrRetransmissions);
        put(TlsAnalyzedProperty.HAS_COOKIE_CHECKS, checksCookie);
        put(TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE, usesVersionInCookie);
        put(TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE, usesRandomInCookie);
        put(TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE, usesSessionIdInCookie);
        put(TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE, usesCiphersuitesInCookie);
        put(TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE, usesCompressionsInCookie);
        put(TlsAnalyzedProperty.USES_PORT_FOR_COOKIE, usesPortInCookie);
        put(TlsAnalyzedProperty.COOKIE_LENGTH, cookieLength);
    }
}
