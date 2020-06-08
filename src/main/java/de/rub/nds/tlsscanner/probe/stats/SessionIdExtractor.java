/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.stats;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import java.util.List;

public class SessionIdExtractor extends StatExtractor<ComparableByteArray> {

    public SessionIdExtractor() {
        super(TrackableValueType.SESSION_ID);
    }

    @Override
    public void extract(State state) {
        WorkflowTrace trace = state.getWorkflowTrace();

        List<ProtocolMessage> allReceivedHandshakeMessages = WorkflowTraceUtil.getAllReceivedMessages(trace,
                ProtocolMessageType.HANDSHAKE);

        for (ProtocolMessage message : allReceivedHandshakeMessages) {
            if (message instanceof ServerHelloMessage && ((ServerHelloMessage) message).getSessionId() != null) {
                put(new ComparableByteArray(((ServerHelloMessage) message).getSessionId().getValue()));
            }
        }
    }

}
