/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.passive;

import de.rub.nds.scanner.core.passive.StatExtractor;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import java.util.List;

public class DtlsRetransmissionsExtractor extends StatExtractor<HandshakeMessageType> {

    public DtlsRetransmissionsExtractor() {
        super(TrackableValueType.DTLS_RETRANSMISSIONS);
    }

    @Override
    public void extract(State state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        List<ProtocolMessage> allReceivedMessages =
                WorkflowTraceUtil.getAllReceivedMessages(trace, ProtocolMessageType.HANDSHAKE);
        for (ProtocolMessage message : allReceivedMessages) {
            if (message instanceof HandshakeMessage
                    && ((HandshakeMessage) message).isRetransmission()) {
                put(((HandshakeMessage) message).getHandshakeMessageType());
            }
        }
    }
}
