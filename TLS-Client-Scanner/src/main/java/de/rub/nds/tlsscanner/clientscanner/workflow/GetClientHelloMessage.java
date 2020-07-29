package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.util.ArrayList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

public class GetClientHelloMessage extends ReceiveAction {
    private static final Logger LOGGER = LogManager.getLogger();

    protected ClientHelloMessage CHLO;
    protected boolean wasCached = false;

    public GetClientHelloMessage() {
        super(new ClientHelloMessage());
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        for (TlsAction action : state.getWorkflowTrace().getTlsActions()) {
            if (action instanceof ReceiveAction) {
                for (ProtocolMessage msg : ((ReceiveAction) action).getReceivedMessages()) {
                    if (msg instanceof ClientHelloMessage) {
                        CHLO = (ClientHelloMessage) msg;
                        break;
                    }
                }
                if (CHLO != null) {
                    break;
                }
            }
        }
        if (CHLO != null) {
            messages = new ArrayList<>(1);
            messages.add(CHLO);
            wasCached = true;
            LOGGER.debug("Found CHLO");
            setExecuted(true);
        } else {
            LOGGER.debug("Did not find CHLO, executing receive action");
            wasCached = false;
            super.execute(state);
        }
    }

    public ClientHelloMessage getClientHelloMessage() {
        return CHLO;
    }

    @Override
    public void reset() {
        CHLO = null;
        super.reset();
    }

    @Override
    public String toString() {
        if (isExecuted() && wasCached) {
            return "Cached Receive Action (Client Hello)\n";
        } else {
            return super.toString();
        }
    }

    @Override
    public String toCompactString() {
        if (isExecuted() && wasCached) {
            return "Cached Receive Action (Client Hello)";
        } else {
            return super.toCompactString();
        }
    }
}