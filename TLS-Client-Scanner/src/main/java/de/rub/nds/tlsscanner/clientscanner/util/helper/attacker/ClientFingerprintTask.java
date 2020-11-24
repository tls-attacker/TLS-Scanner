/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.util.helper.attacker;

import java.util.concurrent.ExecutionException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.helper.ConfiguredTraceDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.helper.ConfiguredTraceDispatcher.ConfiguredTraceDispatcherParameter;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.helper.ConfiguredTraceDispatcher.ConfiguredTraceDispatcherResult;
import de.rub.nds.tlsscanner.clientscanner.util.RandString;

public class ClientFingerprintTask extends FingerPrintTask {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ClientParallelExecutor executorWithParameters;
    private final State inputState;
    private final FingerPrintTask originalTask;
    private State outputState;

    private ResponseFingerprint fingerprint;

    public ClientFingerprintTask(TlsTask _original, ClientParallelExecutor executorWithParameters) {
        super(null, _original.getReexecutions());
        FingerPrintTask original = (FingerPrintTask) _original;
        this.originalTask = original;
        this.executorWithParameters = executorWithParameters;
        this.inputState = original.getState();
    }

    @Override
    public boolean execute() {
        ConfiguredTraceDispatcherResult res;
        String hostnamePrefix = executorWithParameters.hostnamePrefix;
        if (!executorWithParameters.exactHostname) {
            hostnamePrefix = RandString.getRandomAlphaNumeric(10) + "." + hostnamePrefix;
        }
        try {
            res = (ConfiguredTraceDispatcherResult) executorWithParameters.orchestrator
                    .runProbe(
                            ConfiguredTraceDispatcher.getInstance(),
                            hostnamePrefix,
                            executorWithParameters.report,
                            new ConfiguredTraceDispatcherParameter(inputState.getWorkflowTrace(),
                                    inputState.getConfig()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
        outputState = res.state;
        originalTask.setState(outputState);

        if (!outputState.getWorkflowTrace().executedAsPlanned()) {
            LOGGER.warn("WorkflowTrace was not executed as planned {}", outputState.getWorkflowTrace());
            return false;
        }
        fingerprint = ResponseExtractor.getFingerprint(outputState);
        originalTask.setFingerprint(fingerprint);
        if (fingerprint == null) {
            LOGGER.warn("Fingerprint is null after execution");
        }
        return fingerprint != null;
    }

    @Override
    public State getState() {
        if (outputState != null) {
            return outputState;
        } else {
            return inputState;
        }
    }

    @Override
    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    @Override
    public void reset() {
        outputState = null;
        originalTask.reset();
    }

}
