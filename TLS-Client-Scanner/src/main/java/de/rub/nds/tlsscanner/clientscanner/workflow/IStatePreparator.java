package de.rub.nds.tlsscanner.clientscanner.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

public interface IStatePreparator {
    public Config getBaseConfig();

    public State createPreparedState(Config config, WorkflowTrace workflowTrace);

    default public State createPreparedState(WorkflowTrace workflowTrace) {
        return createPreparedState(getBaseConfig(), workflowTrace);
    }

    public void prepareState(State state);
}