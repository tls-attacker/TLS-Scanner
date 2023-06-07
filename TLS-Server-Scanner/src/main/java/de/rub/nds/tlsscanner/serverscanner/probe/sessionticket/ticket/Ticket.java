/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket;

import java.util.List;

import org.apache.commons.math3.util.Pair;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.PossibleSecret;

public interface Ticket {
    /**
     * Apply ticket to the passed config. When executing a handshake with this config, the ticket will be used.
     *
     * @param config
     *               Config to modify.
     */
    void applyTo(Config config);

    /**
     * Set internal ticket bytes.
     *
     * @param ticketBytes
     *                    Bytes which should be sent to the server.
     */
    void setTicketBytes(byte[] ticketBytes);

    /**
     * Get Ticket bytes. This might return the original array and should not be modified. Use
     * {@link #getTicketBytesCopy()} if you want to modify the returned array.
     *
     * @return ticket bytes as sent to the server
     */
    byte[] getTicketBytesOriginal();

    /**
     * Copy a ticket. This is NOT a deep copy; modifications to {@link #getTicketBytesOriginal()} might still modify the
     * original ticket.
     *
     * @return
     */
    Ticket copy();

    /**
     * Get a list of secrets associated to this ticket including strings describing the secrets.
     *
     * @return Secret associated to this ticket including descriptions.
     */
    List<PossibleSecret> getPossibleSecrets();

    /**
     * Check whether the haystack contains a secret associated to this ticket.
     *
     * @param  haystack
     *                  Bytestring to search for a secret.
     * @return          The found secret.
     */
    default PossibleSecret checkContainsSecrets(byte[] haystack) {
        if (haystack == null || haystack.length == 0) {
            return null;
        }
        for (PossibleSecret possibleSecret : getPossibleSecrets()) {
            if (possibleSecret.isContainedIn(haystack)) {
                return possibleSecret;
            }
        }
        return null;
    }

}
