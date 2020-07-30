package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;
import de.rub.nds.tlsscanner.clientscanner.workflow.DummyGetClientHelloAction;

public abstract class BaseProbe implements IDispatcher {
    protected void executeState(State state, DispatchInformation dispatchInformation, boolean insertChlo) {
        dispatchInformation.statePreparator.prepareState(state);
        // fix tls context
        if (dispatchInformation.chloState.getAllTlsContexts().size() != 1) {
            throw new RuntimeException("Cannot handle more than one TLS Context in chloState");
        }
        state.replaceTlsContext(dispatchInformation.chloState.getTlsContext());
        WorkflowTrace trace = state.getWorkflowTrace();
        if (insertChlo) {
            // insert dummy recv client hello
            trace.addTlsAction(0, new DummyGetClientHelloAction(dispatchInformation.chlo));
        }
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
    }
}