
package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

public class CertificatePatchAction extends TlsAction {
    private static final Logger LOGGER = LogManager.getLogger();

    public static CertificatePatchAction insertInto(WorkflowTrace trace, CertificatePatcher patcher) {
        List<TlsAction> actions = trace.getTlsActions();
        int found = -1;
        for (int i = 0; i < actions.size(); i++) {
            TlsAction a = actions.get(i);
            if (a instanceof SendDynamicServerCertificateAction) {
                found = i;
                break;
            }
            if (a instanceof SendingAction) {
                for (ProtocolMessage m : ((SendingAction) a).getSendMessages()) {
                    if (m instanceof CertificateMessage) {
                        found = i;
                        break;
                    }
                }
            }
        }
        if (found > -1) {
            CertificatePatchAction action = new CertificatePatchAction(patcher);
            trace.addTlsAction(found, action);
            return action;
        }
        return null;
    }

    protected final transient CertificatePatcher patcher;

    public CertificatePatchAction(CertificatePatcher patcher) {
        this.patcher = patcher;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        try {
            LOGGER.debug("Patching Certificate");
            patcher.patchCertificate(state);
            setExecuted(true);
        } catch (CertificatePatchException e) {
            throw new WorkflowExecutionException("Failed to patch Certificate", e);
        }
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
