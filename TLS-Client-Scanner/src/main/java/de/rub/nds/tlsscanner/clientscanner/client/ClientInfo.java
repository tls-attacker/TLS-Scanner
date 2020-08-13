package de.rub.nds.tlsscanner.clientscanner.client;

import java.io.Serializable;

public abstract class ClientInfo implements Serializable {
    public abstract String toShortString();
}
