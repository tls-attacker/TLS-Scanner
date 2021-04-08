/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.stats;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import java.util.List;

public class RandomExtractor extends StatExtractor<ComparableByteArray> {

    public RandomExtractor() {
        super(TrackableValueType.RANDOM);
    }

    @Override
    public void extract(State state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        List<ProtocolMessage> allReceivedMessages =
            WorkflowTraceUtil.getAllReceivedMessages(trace, ProtocolMessageType.HANDSHAKE);
        for (ProtocolMessage message : allReceivedMessages) {
            if (message instanceof ServerHelloMessage && ((ServerHelloMessage) message).getRandom() != null) {
                put(new ComparableByteArray(((ServerHelloMessage) message).getRandom().getValue()));
            }
        }
    }

}
