package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.QuicTransportParameterResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class QuicTransportParameterProbe extends QuicServerProbe<ConfigSelector, ServerReport, QuicTransportParameterResult> {


    public QuicTransportParameterProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.TRANSPORT_PARAMETERS, configSelector);
    }

    @Override
    public QuicTransportParameterResult executeTest() {
        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(true);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        config.setQuicVersion(QuicVersion.VERSION_1.getByteValue());
        State state = new State(config);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            QuicTransportParameters transportParameters = state.getContext().getQuicContext().getTransportParameters();
            return new QuicTransportParameterResult(QuicProbeType.TRANSPORT_PARAMETERS, transportParameters);
        } else {
            return new QuicTransportParameterResult(QuicProbeType.TRANSPORT_PARAMETERS, null);
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public QuicTransportParameterResult getCouldNotExecuteResult() {
        return null;
    }

    @Override
    public void adjustConfig(ServerReport report) {

    }
}
