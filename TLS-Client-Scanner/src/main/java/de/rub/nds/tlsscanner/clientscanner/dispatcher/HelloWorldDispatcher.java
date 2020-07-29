package de.rub.nds.tlsscanner.clientscanner.dispatcher;

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

public class HelloWorldDispatcher implements IDispatcher {

    @Override
    public void fillTrace(WorkflowTrace trace, State chloState) {
        trace.addTlsAction(new SendAction(new ServerHelloMessage()));
        trace.addTlsAction(new SendDynamicServerCertificateAction());
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveAction(new RSAClientKeyExchangeMessage(), new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ApplicationMessage()));
        ApplicationMessage msg = new ApplicationMessage();
        msg.setDataConfig(String.join("\r\n",
                "HTTP/1.1 200 OK",
                "Server: TLS-Client-Scanner",
                "Content-Length: 12",
                "",
                "0123456789",
                ""
            ).getBytes());
        trace.addTlsAction(new SendAction(msg));

    }

}