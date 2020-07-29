package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.annotation.XmlTransient;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

public abstract class StateDispatcher<T> implements IDispatcher {

    private Map<String, T> previousStateCache;
    protected T defaultState;

    public StateDispatcher() {
        previousStateCache = new HashMap<>();
    }

    protected T getPreviousState(String raddr) {
        synchronized (previousStateCache) {
            return previousStateCache.getOrDefault(raddr, defaultState);
        }
    }

    protected void setPreviousState(String raddr, T state) {
        synchronized (previousStateCache) {
            previousStateCache.put(raddr, state);
        }
    }

    public void fillTrace(WorkflowTrace trace, State chloState) {
        String raddr = chloState.getInboundTlsContexts().get(0).getConnection().getIp();
        T previousState = getPreviousState(raddr);
        T newState = this.fillTrace(trace, chloState, previousState);
        setPreviousState(raddr, newState);
        trace.addTlsAction(new StateDispatcherPostAction(raddr));
    }

    protected void postExecute(String raddr, State state) {
        T previousState = getPreviousState(raddr);
        setPreviousState(raddr, getNewStatePostExec(previousState, state));
    }

    protected abstract T fillTrace(WorkflowTrace trace, State chloState, T previousState);

    protected abstract T getNewStatePostExec(T previousState, State state);

    @XmlTransient
    public class StateDispatcherPostAction extends TlsAction {
        private String raddr;

        public StateDispatcherPostAction(String raddr) {
            this.raddr = raddr;
        }

        @Override
        public void execute(State state) throws WorkflowExecutionException {
            StateDispatcher.this.postExecute(raddr, state);
        }

        @Override
        public void reset() {
            setExecuted(false);
        }

        @Override
        public boolean executedAsPlanned() {
            return isExecuted();
        }

    }

}