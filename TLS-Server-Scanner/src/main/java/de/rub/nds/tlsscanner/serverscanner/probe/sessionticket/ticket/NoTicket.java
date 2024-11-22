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

    @Override
    public void applyTo(Config config) {
        config.setAddPreSharedKeyExtension(false);
        config.setAddEarlyDataExtension(false);
    }

    @Override
    public void setTicketBytes(byte[] ticketBytes) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getTicketBytesOriginal() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Ticket copy() {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<SessionSecret> getSessionSecrets() {
        throw new UnsupportedOperationException();
    }
}
