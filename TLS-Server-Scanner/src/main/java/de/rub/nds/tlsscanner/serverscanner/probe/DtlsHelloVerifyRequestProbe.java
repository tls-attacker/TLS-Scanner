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
import de.rub.nds.tlsattacker.core.config.Config;
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
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.DtlsHelloVerifyRequestResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;

public class DtlsHelloVerifyRequestProbe extends TlsProbe {

    private Integer cookieLength;

    public DtlsHelloVerifyRequestProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DTLS_HELLO_VERIFY_REQUEST, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            return new DtlsHelloVerifyRequestResult(hasHvrRetransmissions(), checksCookie(), cookieLength,
                usesVersionInCookie(), usesRandomInCookie(), usesSessionIdInCookie(), usesCiphersuitesInCookie(),
                usesCompressionsInCookie());
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new DtlsHelloVerifyRequestResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST, -1,
                TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult hasHvrRetransmissions() {
        Config config = getConfigSelector().getBaseConfig();
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
                return TestResult.TRUE;
            } else {
                return TestResult.FALSE;
            }
        } else {
            return TestResult.CANNOT_BE_TESTED;
        }
    }

    private TestResult checksCookie() {
        Config config = getConfigSelector().getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            if (state.getTlsContext().getDtlsCookie() != null) {
                cookieLength = state.getTlsContext().getDtlsCookie().length;
                if (cookieLength == 0) {
                    return TestResult.CANNOT_BE_TESTED;
                }
            }
        } else {
            return TestResult.ERROR_DURING_TEST;
        }
        config = getConfigSelector().getBaseConfig();
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
        Config config = getConfigSelector().getBaseConfig();
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
        Config config = getConfigSelector().getBaseConfig();
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
        Config config = getConfigSelector().getBaseConfig();
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
        Config config = getConfigSelector().getBaseConfig();
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
        Config config = getConfigSelector().getBaseConfig();
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
                return TestResult.FALSE;
            } else {
                return TestResult.TRUE;
            }
        } else {
            return TestResult.CANNOT_BE_TESTED;
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new DtlsHelloVerifyRequestResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, -1,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

}
