/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionSecret;
import java.util.List;

public class NoTicket implements Ticket {

    /**
     * Applies no ticket configuration by disabling PSK and early data extensions.
     *
     * @param config The TLS configuration to modify
     */
    @Override
    public void applyTo(Config config) {
        config.setAddPreSharedKeyExtension(false);
        config.setAddEarlyDataExtension(false);
    }

    /**
     * Not supported for NoTicket.
     *
     * @param ticketBytes The ticket bytes (ignored)
     * @throws UnsupportedOperationException Always thrown as NoTicket does not support ticket bytes
     */
    @Override
    public void setTicketBytes(byte[] ticketBytes) {
        throw new UnsupportedOperationException();
    }

    /**
     * Not supported for NoTicket.
     *
     * @return Never returns as this operation is not supported
     * @throws UnsupportedOperationException Always thrown as NoTicket does not have ticket bytes
     */
    @Override
    public byte[] getTicketBytesOriginal() {
        throw new UnsupportedOperationException();
    }

    /**
     * Not supported for NoTicket.
     *
     * @return Never returns as this operation is not supported
     * @throws UnsupportedOperationException Always thrown as NoTicket cannot be copied
     */
    @Override
    public Ticket copy() {
        throw new UnsupportedOperationException();
    }

    /**
     * Not supported for NoTicket.
     *
     * @return Never returns as this operation is not supported
     * @throws UnsupportedOperationException Always thrown as NoTicket has no session secrets
     */
    @Override
    public List<SessionSecret> getSessionSecrets() {
        throw new UnsupportedOperationException();
    }
}
