package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import java.util.HashMap;
import java.util.Map;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;

public class DispatchInformation {
    public final ClientHelloMessage chlo;
    public final Map<Class<? extends IDispatcher>, Object> additionalInformation;

    public DispatchInformation(ClientHelloMessage chlo) {
        this.chlo = chlo;
        additionalInformation = new HashMap<>();
    }

    public <T> T getAdditionalInformation(Class<? extends IDispatcher> clazz, Class<T> expectedReturnType) {
        // convenience function
        return expectedReturnType.cast(additionalInformation.get(clazz));
    }
}