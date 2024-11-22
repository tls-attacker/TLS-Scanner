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

public class InvalidCurveTask extends TlsTask {

    private static final Logger LOGGER = LogManager.getLogger();

    private final int appliedSecret;

    private final State state;

    private ResponseFingerprint fingerprint;

    private Point receivedEcKey;

    public InvalidCurveTask(State state, int reexecutions, int appliedSecret) {
        super(reexecutions);
        this.appliedSecret = appliedSecret;
        this.state = state;
    }

    @Override
    public void reset() {
        getState().reset();
    }

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

    public Point getReceivedEcKey() {
        return receivedEcKey;
    }

    public State getState() {
        return state;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    public int getAppliedSecret() {
        return appliedSecret;
    }
}
