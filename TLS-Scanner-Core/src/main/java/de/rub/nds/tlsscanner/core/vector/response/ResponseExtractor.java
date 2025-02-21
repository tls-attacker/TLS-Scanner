/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.response;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.util.List;

public class ResponseExtractor {

    public static ResponseFingerprint getFingerprint(State state, ReceivingAction action) {
        List<ProtocolMessage> messageList = action.getReceivedMessages();
        List<Record> recordList = action.getReceivedRecords();
        SocketState socketState = extractSocketState(state);
        return new ResponseFingerprint(messageList, recordList, socketState);
    }

    public static ResponseFingerprint getFingerprint(State state) {
        ReceivingAction action = state.getWorkflowTrace().getLastReceivingAction();
        return getFingerprint(state, action);
    }

    private static SocketState extractSocketState(State state) {
        if (state.getTlsContext().getTransportHandler() instanceof TcpTransportHandler) {
            SocketState socketState =
                    (((TcpTransportHandler) (state.getTlsContext().getTransportHandler()))
                            .getSocketState());
            return socketState;
        } else {
            return null;
        }
    }

    private ResponseExtractor() {}
}
