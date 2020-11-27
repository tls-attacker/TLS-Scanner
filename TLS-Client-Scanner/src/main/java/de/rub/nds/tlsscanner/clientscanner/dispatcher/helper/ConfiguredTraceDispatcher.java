/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.dispatcher.helper;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.BaseExecutingDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher.ControlledClientDispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class ConfiguredTraceDispatcher extends BaseExecutingDispatcher {
    private static ConfiguredTraceDispatcher instance;

    public static ConfiguredTraceDispatcher getInstance() {
        // singleton is not enforced (yet), but recommended
        if (instance == null) {
            instance = new ConfiguredTraceDispatcher();
        }
        return instance;
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        ControlledClientDispatchInformation info = dispatchInformation.getAdditionalInformation(
                ControlledClientDispatcher.class,
                ControlledClientDispatchInformation.class);
        if (info == null) {
            throw new DispatchException("Was not dispatched by a controlled client");
        }
        if (!(info.additionalParameters instanceof ConfiguredTraceDispatcherParameter)) {
            throw new DispatchException(
                    "Got invalid parameter of type " + info.additionalParameters.getClass().getName());
        }
        ConfiguredTraceDispatcherParameter tc = (ConfiguredTraceDispatcherParameter) info.additionalParameters;
        Config origConfig = state.getConfig();
        Config newConfig = tc.config.createCopy();
        newConfig.getDefaultServerConnection().setHostname(origConfig.getDefaultServerConnection().getHostname());
        state.setConfig(newConfig);
        Config config = state.getConfig();
        config.setResetTrace(false);
        config.setSkipExecutedActions(true);
        extendWorkflowTraceValidatingPrefix(state.getWorkflowTrace(), state.getWorkflowTrace(), tc.trace);
        executeState(state, dispatchInformation);
        return new ConfiguredTraceDispatcherResult(state);
    }

    public static class ConfiguredTraceDispatcherParameter {
        public final WorkflowTrace trace;
        public final Config config;

        public ConfiguredTraceDispatcherParameter(WorkflowTrace trace, Config config) {
            this.trace = trace;
            this.config = config;
        }
    }

    public static class ConfiguredTraceDispatcherResult extends ClientProbeResult {
        public final transient State state;

        public ConfiguredTraceDispatcherResult(State state) {
            this.state = state;
        }

        @Override
        public void merge(ClientReport report) {
            throw new RuntimeException("This internal result may not be merged");
        }
    }

}
