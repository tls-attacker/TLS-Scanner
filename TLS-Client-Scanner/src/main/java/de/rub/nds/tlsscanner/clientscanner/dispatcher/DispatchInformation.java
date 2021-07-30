/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import java.util.HashMap;
import java.util.Map;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;

public class DispatchInformation {
    protected ClientHelloMessage chlo;
    public final Map<Class<? extends Dispatcher>, Object> additionalInformation;

    public DispatchInformation() {
        additionalInformation = new HashMap<>();
    }

    public <T> T getAdditionalInformation(Class<? extends Dispatcher> clazz, Class<T> expectedReturnType) {
        // convenience function
        return expectedReturnType.cast(additionalInformation.get(clazz));
    }

    public ClientHelloMessage getChlo() {
        return this.chlo;
    }

    /**
     * Tries to get ClientHelloMessage. If it is not present, the ChloEntryDispatcher is used to get the
     * ClientHelloMessage. This must be called before the WorkflowTrace within the State is extended, otherwise actions
     * might be executed in the wrong order.
     *
     * @param  state
     *                           Used to execute ChloEntryDispatcher
     * @return                   Retrieved (or cached) ClientHelloMessage
     * @throws DispatchException
     *                           May be thrown by the ChloEntryDispatcher
     */
    public ClientHelloMessage getChlo(State state) throws DispatchException {
        if (getChlo() == null) {
            new ChloEntryDispatcher(null).execute(state, this);
        }
        return getChlo();
    }

    public void setChlo(ClientHelloMessage chlo) {
        this.chlo = chlo;
    }
}