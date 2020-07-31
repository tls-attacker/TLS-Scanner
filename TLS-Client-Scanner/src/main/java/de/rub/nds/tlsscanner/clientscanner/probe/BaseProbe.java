package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceNormalizer;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;

public abstract class BaseProbe implements IDispatcher {
    protected void executeState(State state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
        normalizer.normalize(trace, state.getConfig(), state.getRunningMode());
        trace.setDirty(false);

        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
    }
}