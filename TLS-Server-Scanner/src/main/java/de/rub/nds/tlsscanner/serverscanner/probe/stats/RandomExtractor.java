/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe.stats;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import java.util.List;

/**
 * Currently not in use for any probe. The probe TlsRng extracts randomness by
 * other means.
 */
public class RandomExtractor extends StatExtractor<ComparableByteArray> {

    public RandomExtractor() {
        super(TrackableValueType.RANDOM);
    }

    @Override
    public void extract(State state) {
        WorkflowTrace trace = state.getWorkflowTrace();

        List<ProtocolMessage> allReceivedHandshakeMessages = WorkflowTraceUtil.getAllReceivedMessages(trace,
                ProtocolMessageType.HANDSHAKE);

        for (ProtocolMessage message : allReceivedHandshakeMessages) {
            if (message instanceof ServerHelloMessage && ((ServerHelloMessage) message).getRandom() != null) {
                put(new ComparableByteArray(((ServerHelloMessage) message).getRandom().getValue()));
            }
        }
    }

}
