package de.rub.nds.tlsscanner.clientscanner.probe;

import org.apache.commons.lang3.tuple.Pair;

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.workflow.GetClientHelloMessage;

public class HelloWorldProbe extends BaseStatefulProbe<Integer> {

    public HelloWorldProbe() {
        super();
        this.defaultState = 0;
    }

    @Override
    protected Pair<ClientProbeResult, Integer> execute(State state, DispatchInformation dispatchInformation,
            Integer previousState) {
        WorkflowTrace trace = state.getWorkflowTrace();
        trace.addTlsAction(new GetClientHelloMessage());
        trace.addTlsAction(new GetClientHelloMessage());
        trace.addTlsAction(new SendAction(new ServerHelloMessage()));
        trace.addTlsAction(new SendDynamicServerCertificateAction());
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveAction(new RSAClientKeyExchangeMessage(), new ChangeCipherSpecMessage(),
                new FinishedMessage()));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ApplicationMessage()));
        ApplicationMessage msg = new ApplicationMessage();
        String content = "Call No:" + (previousState + 1);
        msg.setDataConfig(String.join("\r\n", "HTTP/1.1 200 OK", "Server: TLS-Client-Scanner",
                "Content-Length: " + (content.length() + 2), "", content, "").getBytes());
        trace.addTlsAction(new SendAction(msg));
        executeState(state);
        return Pair.of(null, previousState + 1);
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public ClientProbeResult call() throws Exception {
        // TODO Auto-generated method stub
        return null;
    }

}