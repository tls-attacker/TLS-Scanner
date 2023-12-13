/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import com.google.common.primitives.Bytes;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DtlsApplicationFingerprintProbe extends TlsServerProbe {

    private List<ApplicationProtocol> supportedApplications;
    private TestResult isAcceptingUnencryptedAppData = TestResults.COULD_NOT_TEST;

    public DtlsApplicationFingerprintProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_APPLICATION_FINGERPRINT, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTED_APPLICATIONS,
                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA);
    }

    @Override
    protected void executeTest() {
        supportedApplications = new ArrayList<>();
        isAcceptingUnencryptedAppData = TestResults.NOT_TESTED_YET;
        if (!isEchoServer()) {
            isVpnSupported();
            isStunSupported();
            isTurnSupported();
            isCoapSupported();
        }
    }

    private boolean isEchoServer() {
        byte[] appData =
                ArrayConverter.hexStringToByteArray("9988776655443322110000112233445566778899");
        byte[] data = isProtocolSupported(appData);
        if (Arrays.equals(data, appData)) {
            supportedApplications.add(ApplicationProtocol.ECHO);
            return true;
        }
        return false;
    }

    private void isVpnSupported() {
        byte[] length = ArrayConverter.hexStringToByteArray("0118");
        byte[] string =
                ArrayConverter.hexStringToByteArray(
                        "0047467479706500636c7468656c6c6f005356504e434f4f4b494500");
        byte[] cookie =
                ArrayConverter.hexStringToByteArray("34626a384f64735a486a6f644e736859512b59");
        byte[] appData = ArrayConverter.concatenate(length, string, cookie);
        byte[] data = isProtocolSupported(appData);
        byte[] fortinetHandshakeFail =
                ArrayConverter.hexStringToByteArray(
                        "00214746747970650073767268656C6C6F0068616E647368616B65006661696C00");
        byte[] fortinetHandshakeOk =
                ArrayConverter.hexStringToByteArray(
                        "001f4746747970650073767268656C6C6F0068616E647368616B65006f6b00");
        byte[] citrixResponse =
                ArrayConverter.hexStringToByteArray("FF0000010000000000000000000000000000000001");
        if (Bytes.indexOf(data, fortinetHandshakeFail) != -1) {
            supportedApplications.add(ApplicationProtocol.VPN_FORTINET);
            isAcceptingUnencryptedAppData(appData);
        } else if (Bytes.indexOf(data, fortinetHandshakeOk) != -1) {
            supportedApplications.add(ApplicationProtocol.VPN_FORTINET);
            isAcceptingUnencryptedAppData(appData);
        } else if (Bytes.indexOf(data, citrixResponse) != -1) {
            supportedApplications.add(ApplicationProtocol.VPN_CITRIX);
            isAcceptingUnencryptedAppData(appData);
        }
    }

    private void isStunSupported() {
        byte[] type = ArrayConverter.hexStringToByteArray("0001");
        byte[] length = ArrayConverter.hexStringToByteArray("0000");
        byte[] cookie = ArrayConverter.hexStringToByteArray("2112a442");
        byte[] transactionId = ArrayConverter.hexStringToByteArray("112233445566778899001122");
        byte[] appData = ArrayConverter.concatenate(type, length, cookie, transactionId);
        byte[] data = isProtocolSupported(appData);
        if (Bytes.indexOf(data, transactionId) != -1) {
            supportedApplications.add(ApplicationProtocol.STUN);
            isAcceptingUnencryptedAppData(appData);
        }
    }

    private void isTurnSupported() {
        byte[] type = ArrayConverter.hexStringToByteArray("0003");
        byte[] length = ArrayConverter.hexStringToByteArray("0008");
        byte[] cookie = ArrayConverter.hexStringToByteArray("2112a442");
        byte[] transactionId = ArrayConverter.hexStringToByteArray("112233445566778899001122");
        byte[] requestedTransport = ArrayConverter.hexStringToByteArray("0019000411000000");
        byte[] appData =
                ArrayConverter.concatenate(type, length, cookie, transactionId, requestedTransport);
        byte[] data = isProtocolSupported(appData);
        if (Bytes.indexOf(data, transactionId) != -1) {
            supportedApplications.add(ApplicationProtocol.TURN);
            isAcceptingUnencryptedAppData(appData);
        }
    }

    private void isCoapSupported() {
        byte[] header = ArrayConverter.hexStringToByteArray("4000");
        byte[] messageId = ArrayConverter.hexStringToByteArray("9812");
        byte[] appData = ArrayConverter.concatenate(header, messageId);
        byte[] data = isProtocolSupported(appData);
        if (Bytes.indexOf(data, messageId) != -1) {
            supportedApplications.add(ApplicationProtocol.COAP);
            isAcceptingUnencryptedAppData(appData);
        }
    }

    private byte[] isProtocolSupported(byte[] data) {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(new ApplicationMessage(data)));
        ReceiveAction receiveAction = new ReceiveAction(new ApplicationMessage());
        trace.addTlsAction(receiveAction);
        State state = new State(config, trace);
        executeState(state);
        if (receiveAction.getReceivedRecords() != null
                && !receiveAction.getReceivedRecords().isEmpty()) {
            ByteArrayOutputStream receivedAppData = new ByteArrayOutputStream();
            try {
                for (Record record : receiveAction.getReceivedRecords()) {
                    receivedAppData.write(record.getCleanProtocolMessageBytes().getValue());
                }
            } catch (IOException ex) {
                LOGGER.error("Could not write cleanProtocolMessageBytes to receivedAppData");
            }
            return receivedAppData.toByteArray();
        } else {
            return new byte[0];
        }
    }

    private void isAcceptingUnencryptedAppData(byte[] data) {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(new ApplicationMessage(data)));
        trace.addTlsAction(new ReceiveAction(new ApplicationMessage()));
        State state = new State(config, trace);
        executeState(state);
        ProtocolMessage receivedMessage =
                WorkflowTraceResultUtil.getLastReceivedMessage(state.getWorkflowTrace());

        trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        SendAction sendAction = new SendAction(new ApplicationMessage(data));
        Record record = new Record(config);
        record.setEpoch(Modifiable.explicit(0));
        sendAction.setConfiguredRecords(List.of(record));
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new ReceiveAction(new ApplicationMessage()));
        state = new State(config, trace);
        executeState(state);
        ProtocolMessage receivedMessageModified =
                WorkflowTraceResultUtil.getLastReceivedMessage(state.getWorkflowTrace());
        if (receivedMessage != null
                && receivedMessageModified != null
                && receivedMessage
                        .getCompleteResultingMessage()
                        .equals(receivedMessageModified.getCompleteResultingMessage())) {
            isAcceptingUnencryptedAppData = TestResults.TRUE;
        }
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS, supportedApplications);
        put(TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA, isAcceptingUnencryptedAppData);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS);
    }
}
