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
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.FoundSecret;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionSecret;
import java.util.List;
import java.util.Optional;

public interface Ticket {
    /**
     * Apply ticket to the passed config. When executing a handshake with this config, the ticket
     * will be used.
     *
     * @param config Config to modify.
     */
    void applyTo(Config config);

    /**
     * Set internal ticket bytes.
     *
     * @param ticketBytes Bytes which should be sent to the server.
     */
    void setTicketBytes(byte[] ticketBytes);

    /**
     * Get Ticket bytes. This might return the original array and should not be modified.
     *
     * @return ticket bytes as sent to the server
     */
    byte[] getTicketBytesOriginal();

    /**
     * Copy a ticket. This is NOT a deep copy; modifications to {@link #getTicketBytesOriginal()}
     * might still modify the original ticket.
     *
     * @return
     */
    Ticket copy();

    /**
     * Get a list of secrets associated to this ticket including strings describing the secrets.
     *
     * @return Secret associated to this ticket including descriptions.
     */
    List<SessionSecret> getSessionSecrets();

    /**
     * Check whether the haystack contains a secret associated to this ticket.
     *
     * @param haystack Bytestring to search for a secret.
     * @return The found secret.
     */
    default FoundSecret checkContainsSecrets(byte[] haystack) {
        if (haystack == null || haystack.length == 0) {
            return null;
        }
        for (SessionSecret sessionSecret : getSessionSecrets()) {
            Optional<Integer> offset = sessionSecret.findIn(haystack);
            if (offset.isPresent()) {
                return new FoundSecret(sessionSecret, offset.get());
            }
        }
        return null;
    }
}
