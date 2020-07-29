package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

public interface IDispatcher {
    public void fillTrace(WorkflowTrace trace, State chloState);
}