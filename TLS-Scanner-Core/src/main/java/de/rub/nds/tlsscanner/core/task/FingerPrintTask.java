/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.task;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.core.vector.response.ResponseExtractor;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FingerPrintTask extends TlsTask {

    private static final Logger LOGGER = LogManager.getLogger();

    private final State state;

    private ResponseFingerprint fingerprint;

    /**
     * Constructs a new FingerPrintTask with the specified state and number of reexecutions.
     *
     * @param state The TLS state to execute the fingerprinting task on
     * @param reexecutions The number of times to retry execution if it fails
     */
    public FingerPrintTask(State state, int reexecutions) {
        super(reexecutions);
        this.state = state;
    }

    /**
     * Constructs a new FingerPrintTask with extended timeout configuration.
     *
     * @param state The TLS state to execute the fingerprinting task on
     * @param additionalTimeout Additional timeout in milliseconds for the task execution
     * @param increasingTimeout Whether to increase timeout on retries
     * @param reexecutions The number of times to retry execution if it fails
     * @param additionalTcpTimeout Additional TCP timeout in milliseconds
     */
    public FingerPrintTask(
            State state,
            long additionalTimeout,
            boolean increasingTimeout,
            int reexecutions,
            long additionalTcpTimeout) {
        super(reexecutions, additionalTimeout, increasingTimeout, additionalTcpTimeout);
        this.state = state;
    }

    /**
     * Executes the fingerprinting task by running the workflow and extracting the response
     * fingerprint.
     *
     * @return true if the task executed successfully and a fingerprint was extracted, false
     *     otherwise
     */
    @Override
    public boolean execute() {
        try {
            WorkflowExecutor executor = getExecutor(state);
            executor.executeWorkflow();

            if (!state.getWorkflowTrace().executedAsPlanned()) {
                return false;
            }
            fingerprint = ResponseExtractor.getFingerprint(state);

            if (fingerprint == null) {
                return false;
            }
            return true;
        } finally {
            try {
                state.getTlsContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
        }
    }

    /**
     * Gets the state associated with this task.
     *
     * @return The TLS state
     */
    public State getState() {
        return state;
    }

    /**
     * Gets the response fingerprint extracted during task execution.
     *
     * @return The response fingerprint, or null if the task has not been executed successfully
     */
    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    /** Resets the task by resetting its associated TLS state. */
    @Override
    public void reset() {
        state.reset();
    }
}
