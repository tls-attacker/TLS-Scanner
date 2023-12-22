/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.config.ExecutorConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.List;

public class SimulationRequest {

    private TlsClientConfig tlsClientConfig;

    public SimulationRequest(TlsClientConfig tlsClientConfig) {
        this.tlsClientConfig = tlsClientConfig;
    }

    public State getExecutableState(ExecutorConfig executorConfig) {
        Config config = tlsClientConfig.getConfig();
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setStopTraceAfterUnexpected(true);
        config.setStopActionsAfterWarning(false);
        config.setEnforceSettings(false);

        WorkflowTrace trace = new WorkflowTrace();

        if (tlsClientConfig.getIsSSL2CompatibleClientHello()) {
            SendAction sendAction = new SendAction(new SSL2ClientHelloMessage());
            Record record = new Record();
            record.setCompleteRecordBytes(Modifiable.explicit(tlsClientConfig.getInitialBytes()));
            sendAction.setConfiguredRecords(List.of(record));
            trace.addTlsAction(sendAction);
        } else {
            ClientHelloMessage msg = new ClientHelloMessage(config);
            List<ExtensionMessage> extensions =
                    WorkflowTraceResultUtil.getLastReceivedMessage(
                                    tlsClientConfig.getTrace(), HandshakeMessageType.CLIENT_HELLO)
                            .getExtensions();
            msg.setExtensions(extensions);
            trace.addTlsAction(new SendAction(msg));
        }
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        State state = new State(config, trace);
        return state;
    }

    public TlsClientConfig getTlsClientConfig() {
        return tlsClientConfig;
    }

    public void setTlsClientConfig(TlsClientConfig tlsClientConfig) {
        this.tlsClientConfig = tlsClientConfig;
    }
}
