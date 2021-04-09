/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.DtlsCoookieResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DtlsCookieProbe extends TlsProbe {

    public DtlsCookieProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DTLS_COOKIE, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            TestResult checksCookie = isCookieChecked();
            TestResult checksCookieWithClientParameters = TestResult.TRUE;
            if (isVersionUsed() == TestResult.FALSE || isRandomUsed() == TestResult.FALSE
                    || isCiphersuitesUsed() == TestResult.FALSE || isCompressionMethodsUsed() == TestResult.FALSE) {
                checksCookieWithClientParameters = TestResult.FALSE;
            }
            return new DtlsCoookieResult(checksCookie, checksCookieWithClientParameters);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new DtlsCoookieResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult isCookieChecked() {
        Config config = getConfig();
        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        State state = new State(config);
        executeState(state);
        int cookieLength = 0;
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            cookieLength = state.getTlsContext().getDtlsCookie().length;
        } else {
            return TestResult.ERROR_DURING_TEST;
        }
        int[] testPositions = new int[] { 0, cookieLength / 2, cookieLength - 1 };
        for (int totest : testPositions) {
            config = getConfig();
            WorkflowTrace trace = new WorkflowConfigurationFactory(config).createTlsEntryWorkflowtrace(config
                    .getDefaultClientConnection());
            trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
            ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
            ModifiableByteArray cookie = new ModifiableByteArray();
            cookie.setModification(ByteArrayModificationFactory.xor(ArrayConverter.hexStringToByteArray("FF"), totest));
            clientHelloMessage.setCookie(cookie);
            trace.addTlsAction(new SendAction(clientHelloMessage));
            trace.addTlsAction(new ReceiveAction(new ServerHelloMessage(config)));
            state = new State(config, trace);
            if (getResult(state) == TestResult.FALSE) {
                return TestResult.FALSE;
            }
        }
        return TestResult.TRUE;
    }

    private TestResult isVersionUsed() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createTlsEntryWorkflowtrace(config
                .getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        ModifiableByteArray protocolVersion = new ModifiableByteArray();
        protocolVersion.setModification(ByteArrayModificationFactory.explicitValue(ProtocolVersion.DTLS10.getValue()));
        clientHelloMessage.setProtocolVersion(protocolVersion);
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveAction(new ServerHelloMessage(config)));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult isRandomUsed() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createTlsEntryWorkflowtrace(config
                .getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        ModifiableByteArray random = new ModifiableByteArray();
        random.setModification(ByteArrayModificationFactory.xor(ArrayConverter.hexStringToByteArray("FFFF"), -2));
        clientHelloMessage.setRandom(random);
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveAction(new ServerHelloMessage(config)));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult isCiphersuitesUsed() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createTlsEntryWorkflowtrace(config
                .getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        ModifiableByteArray ciphersuites = new ModifiableByteArray();
        ciphersuites.setModification(ByteArrayModificationFactory.delete(1, 2));
        clientHelloMessage.setCipherSuites(ciphersuites);
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveAction(new ServerHelloMessage(config)));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult isCompressionMethodsUsed() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createTlsEntryWorkflowtrace(config
                .getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        ModifiableByteArray compressions = new ModifiableByteArray();
        compressions.setModification(ByteArrayModificationFactory.delete(-1, 1));
        clientHelloMessage.setCompressions(compressions);
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveAction(new ServerHelloMessage(config)));
        State state = new State(config, trace);
        return getResult(state);
    }

    private TestResult getResult(State state) {
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.FALSE;
        } else {
            return TestResult.TRUE;
        }
    }

    private Config getConfig() {
        Config config = getScannerConfig().createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        List<CipherSuite> ciphersuites = new LinkedList<>();
        ciphersuites.addAll(Arrays.asList(CipherSuite.values()));
        ciphersuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        ciphersuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setDefaultClientSupportedCiphersuites(ciphersuites);
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
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new DtlsCoookieResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

}
