package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.util.ArrayList;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DummyGetClientHelloAction extends ReceiveAction {
    private static final Logger LOGGER = LogManager.getLogger();
    private ClientHelloMessage chlo;

    public DummyGetClientHelloAction(ClientHelloMessage chlo) {
        super(chlo);
        this.chlo = chlo;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        messages = new ArrayList<>(1);
        messages.add(chlo);
        records = new ArrayList<>(0);
        LOGGER.info("(Dummy) Received messages: {}", getReadableString(messages));
        setExecuted(true);
    }
}