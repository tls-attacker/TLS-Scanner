package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.util.ArrayList;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;

public class DummyGetClientHelloAction extends ReceiveAction {
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
        setExecuted(true);
    }
}