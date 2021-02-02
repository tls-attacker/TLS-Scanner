/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.biginteger.BigIntegerAddModification;
import de.rub.nds.modifiablevariable.biginteger.BigIntegerSubtractModification;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.integer.IntegerAddModification;
import de.rub.nds.modifiablevariable.integer.IntegerSubtractModification;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.DtlsFragmentationResult;
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
public class DtlsFragmentationProbe extends TlsProbe {

    public DtlsFragmentationProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DTLS_FRAGMENTATION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            // test();
            fragmentLengthIntolerance();
            // messageSequenceIntolerance();
            // sequenceNumberIntolerance();
            return new DtlsFragmentationResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new DtlsFragmentationResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }
    }

    private void test() {
        Config config = getConfig();
        config.setDtlsMaximumFragmentLength(70);
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createTlsEntryWorkflowtrace(config
                .getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        executeState(state);
    }

    // Vertauschen der Sequence Nummern (Record Header)
    private TestResult sequenceNumberIntolerance() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createTlsEntryWorkflowtrace(config
                .getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
        SendAction sendAction = new SendAction(new ClientHelloMessage(config));
        sendAction.setFragments(new LinkedList<DtlsHandshakeMessageFragment>());
        sendAction.getFragments().add(new DtlsHandshakeMessageFragment(config, 80));
        sendAction.getFragments().add(new DtlsHandshakeMessageFragment(config, 80));
        sendAction.getFragments().add(new DtlsHandshakeMessageFragment(config, 80));
        sendAction.setRecords(new LinkedList<AbstractRecord>());
        Record record1 = new Record(config);
        ModifiableBigInteger seqNumber1 = new ModifiableBigInteger();
        seqNumber1.setModification(new BigIntegerAddModification(new BigInteger("2")));
        record1.setSequenceNumber(seqNumber1);
        sendAction.getRecords().add(record1);
        Record record2 = new Record(config);
        ModifiableBigInteger seqNumber2 = new ModifiableBigInteger();
        // seqNumber2.setModification(new BigIntegerAddModification(new
        // BigInteger("1")));
        record2.setSequenceNumber(seqNumber2);
        sendAction.getRecords().add(record2);
        Record record3 = new Record(config);
        ModifiableBigInteger seqNumber3 = new ModifiableBigInteger();
        seqNumber3.setModification(new BigIntegerSubtractModification(new BigInteger("2")));
        record3.setSequenceNumber(seqNumber3);
        sendAction.getRecords().add(record3);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    // Message Sequence+1 ab 2te CH (Fragment Header)
    private TestResult messageSequenceIntolerance() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createTlsEntryWorkflowtrace(config
                .getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        // 2th CH
        SendAction sendAction1 = new SendAction(new ClientHelloMessage(config));
        sendAction1.setFragments(new LinkedList<DtlsHandshakeMessageFragment>());
        DtlsHandshakeMessageFragment fragment1 = new DtlsHandshakeMessageFragment(config);
        ModifiableInteger messageSeq = new ModifiableInteger();
        messageSeq.setModification(new IntegerAddModification(1));
        fragment1.setMessageSeq(messageSeq);
        sendAction1.getFragments().add(fragment1);
        trace.addTlsAction(sendAction1);
        // SH, CERT, SKE, SHD
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        // CKE
        SendDynamicClientKeyExchangeAction sendDynamicClientKeyExchangeAction = new SendDynamicClientKeyExchangeAction();
        sendDynamicClientKeyExchangeAction.setFragments(new LinkedList<DtlsHandshakeMessageFragment>());
        DtlsHandshakeMessageFragment fragment2 = new DtlsHandshakeMessageFragment(config);
        ModifiableInteger messageSeq2 = new ModifiableInteger();
        messageSeq2.setModification(new IntegerAddModification(1));
        fragment2.setMessageSeq(messageSeq2);
        sendDynamicClientKeyExchangeAction.getFragments().add(fragment2);
        trace.addTlsAction(sendDynamicClientKeyExchangeAction);
        // CSS, FIN
        SendAction sendAction2 = new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config));
        sendAction2.setFragments(new LinkedList<DtlsHandshakeMessageFragment>());
        DtlsHandshakeMessageFragment fragment3 = new DtlsHandshakeMessageFragment(config);
        ModifiableInteger messageSeq3 = new ModifiableInteger();
        messageSeq3.setModification(new IntegerAddModification(1));
        fragment3.setMessageSeq(messageSeq3);
        sendAction2.getFragments().add(fragment3);
        trace.addTlsAction(sendAction2);
        // CSS, FIN
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    // Length > Fragment Length
    private TestResult fragmentLengthIntolerance() {
        Config config = getConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createTlsEntryWorkflowtrace(config
                .getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        SendAction sendAction = new SendAction(new ClientHelloMessage(config));
        sendAction.setFragments(new LinkedList<DtlsHandshakeMessageFragment>());
        DtlsHandshakeMessageFragment fragment1 = new DtlsHandshakeMessageFragment(config, 120);
        ModifiableInteger length1 = new ModifiableInteger();
        length1.setModification(new IntegerSubtractModification(20));
        fragment1.setLength(length1);
        sendAction.getFragments().add(fragment1);
        DtlsHandshakeMessageFragment fragment2 = new DtlsHandshakeMessageFragment(config, 120);
        ModifiableInteger length2 = new ModifiableInteger();
        length2.setModification(new IntegerSubtractModification(20));
        fragment2.setLength(length2);
        sendAction.getFragments().add(fragment2);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    private Config getConfig() {
        Config config = getScannerConfig().createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        List<CipherSuite> ciphersuites = new LinkedList<>();
        // TODO: Später löschen
        config.setStopTraceAfterUnexpected(true);
        ciphersuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
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
        return new DtlsFragmentationResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

}
