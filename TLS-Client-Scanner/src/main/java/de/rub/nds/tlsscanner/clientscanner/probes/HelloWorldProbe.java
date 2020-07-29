package de.rub.nds.tlsscanner.clientscanner.probes;

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
import de.rub.nds.tlsscanner.clientscanner.dispatcher.StateDispatcher;
import de.rub.nds.tlsscanner.clientscanner.workflow.GetClientHelloMessage;

public class HelloWorldProbe extends StateDispatcher<Integer> {

    public HelloWorldProbe() {
        super();
        this.defaultState = 0;
    }

    @Override
    protected Integer fillTrace(WorkflowTrace trace, State chloState, Integer previousState) {
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
        return previousState;
    }

    @Override
    protected Integer getNewStatePostExec(Integer previousState, State state) {
        return previousState += 1;
    }

}