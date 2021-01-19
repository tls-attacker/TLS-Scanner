/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.DtlsCcsResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DtlsCcsProbe extends TlsProbe {

    public DtlsCcsProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DTLS_CCS, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            return new DtlsCcsResult(isAcceptUnencryptedAppData(), isEarlyFinished(), isAcceptMultipleCCS());
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new DtlsCcsResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                    TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult isAcceptUnencryptedAppData() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(
                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        SendAction sendAction = new SendAction(new ApplicationMessage(config));
        Record record = new Record(config);
        ModifiableInteger integer = new ModifiableInteger();
        integer.setModification(IntegerModificationFactory.explicitValue(0));
        record.setEpoch(integer);
        ModifiableBigInteger bigInteger = new ModifiableBigInteger();
        bigInteger.setModification(BigIntegerModificationFactory.explicitValue(BigInteger.valueOf(4)));
        record.setSequenceNumber(bigInteger);
        sendAction.setRecords(record);
        trace.addTlsAction(sendAction);
        State state = new State(config, trace);
        executeState(state);
        // TODO: Wie überprüfe ich ob es akzeptiert hat? Bei DTLS kommt nicht
        // zwingend eine Fehlernachricht
        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.APPLICATION_DATA, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    private TestResult isEarlyFinished() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(
                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new FinishedMessage(config)));
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    private TestResult isAcceptMultipleCCS() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(
                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new ChangeCipherSpecMessage(),
                new FinishedMessage(config)));
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            Record msg = (Record) WorkflowTraceUtil.getLastReceivedRecord(state.getWorkflowTrace());
            // TODO: Type Überprüfung notwendig?
            if (ProtocolMessageType.getContentType(msg.getContentType().getValue()) == ProtocolMessageType.HANDSHAKE
                    && msg.getEpoch().getValue() == 2) {
                return TestResult.TRUE;
            } else {
                return TestResult.FALSE;
            }
        } else {
            return TestResult.FALSE;
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
        config.setEarlyStop(true);
        config.setStopReceivingAfterFatal(false);
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
        return new DtlsCcsResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

}
