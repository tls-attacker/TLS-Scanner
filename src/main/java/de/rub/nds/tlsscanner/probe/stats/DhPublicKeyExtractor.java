package de.rub.nds.tlsscanner.probe.stats;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import java.math.BigInteger;
import java.util.List;

public class DhPublicKeyExtractor extends StatExtractor<BigInteger> {

    public DhPublicKeyExtractor() {
        super(TrackableValueType.DH_PUBKEY);
    }

    @Override
    public void extract(State state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        List<ProtocolMessage> allReceivedMessages = WorkflowTraceUtil.getAllReceivedMessages(trace, ProtocolMessageType.HANDSHAKE);
        for (ProtocolMessage message : allReceivedMessages) {
            if (message instanceof DHEServerKeyExchangeMessage) {
                put(new BigInteger(1, ((DHEServerKeyExchangeMessage) message).getPublicKey().getValue()));
            }
        }
    }

}
