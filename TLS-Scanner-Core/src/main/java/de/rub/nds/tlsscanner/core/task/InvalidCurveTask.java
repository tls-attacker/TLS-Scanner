/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.task;

import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsscanner.core.vector.response.ResponseExtractor;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A task for testing invalid elliptic curve configurations. This task executes a TLS workflow and
 * captures the server's response to invalid curve parameters.
 */
public class InvalidCurveTask extends TlsTask {

    private static final Logger LOGGER = LogManager.getLogger();

    private final int appliedSecret;

    private final State state;

    private ResponseFingerprint fingerprint;

    private Point receivedEcKey;

    /**
     * Constructs a new InvalidCurveTask with the specified parameters.
     *
     * @param state The TLS state to execute the task on
     * @param reexecutions The number of times to retry execution if it fails
     * @param appliedSecret The secret value applied for the invalid curve test
     */
    public InvalidCurveTask(State state, int reexecutions, int appliedSecret) {
        super(reexecutions);
        this.appliedSecret = appliedSecret;
        this.state = state;
    }

    /** Resets the task by resetting its associated TLS state. */
    @Override
    public void reset() {
        getState().reset();
    }

    /**
     * Executes the invalid curve task by running the workflow and extracting the server's response.
     * Captures the server's ephemeral EC public key if present.
     *
     * @return true if the task executed successfully and a valid fingerprint was extracted, false
     *     otherwise
     */
    @Override
    public boolean execute() {
        try {
            WorkflowExecutor executor = getExecutor(state);
            executor.executeWorkflow();
            // TODO only ephemeral
            if (getState().getTlsContext().getServerEphemeralEcPublicKey() != null) {
                receivedEcKey = getState().getTlsContext().getServerEphemeralEcPublicKey();
            }

            if (!state.getWorkflowTrace().executedAsPlanned()) {
                LOGGER.debug("Not executed as planned!");
                return false;
            }
            fingerprint = ResponseExtractor.getFingerprint(getState());

            if (fingerprint == null || fingerprint.getSocketState() == SocketState.DATA_AVAILABLE) {
                fingerprint = null;
                return false;
            }
            return true;
        } finally {
            try {
                getState().getTlsContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
        }
    }

    /**
     * Gets the elliptic curve public key received from the server during task execution.
     *
     * @return The received EC public key point, or null if no key was received
     */
    public Point getReceivedEcKey() {
        return receivedEcKey;
    }

    /**
     * Gets the TLS state associated with this task.
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

    /**
     * Gets the secret value that was applied for the invalid curve test.
     *
     * @return The applied secret value
     */
    public int getAppliedSecret() {
        return appliedSecret;
    }
}
