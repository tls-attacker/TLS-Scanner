/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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