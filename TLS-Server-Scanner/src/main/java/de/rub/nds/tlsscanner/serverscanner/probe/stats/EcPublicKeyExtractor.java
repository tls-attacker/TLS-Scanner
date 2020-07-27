/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe.stats;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import java.util.List;

public class EcPublicKeyExtractor extends StatExtractor<Point> {

    public EcPublicKeyExtractor() {
        super(TrackableValueType.ECDHE_PUBKEY);
    }

    @Override
    public void extract(State state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        List<ProtocolMessage> allReceivedMessages = WorkflowTraceUtil.getAllReceivedMessages(trace,
                ProtocolMessageType.HANDSHAKE);
        for (ProtocolMessage message : allReceivedMessages) {
            if (message instanceof ECDHEServerKeyExchangeMessage) {
                NamedGroup group = NamedGroup.getNamedGroup(((ECDHEServerKeyExchangeMessage) message).getNamedGroup()
                        .getValue());
                byte[] pointBytes = ((ECDHEServerKeyExchangeMessage) message).getPublicKey().getValue();
                put(PointFormatter.formatFromByteArray(group, pointBytes));
            }
        }
    }
}
