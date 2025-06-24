/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionSecret;
import java.util.Arrays;
import java.util.List;

public class TicketTls13 implements Ticket {
    private PskSet pskSet;
    private List<SessionSecret> sessionSecrets;

    @SuppressWarnings("unused")
    // This constructor is used by Jackson for deserialization
    private TicketTls13() {
        this.pskSet = new PskSet();
        this.sessionSecrets = List.of();
    }

    /**
     * Constructs a new TLS 1.3 ticket with the specified PSK set and session secrets.
     *
     * @param pskSet The pre-shared key set containing ticket information
     * @param sessionSecrets List of session secrets associated with this ticket
     */
    public TicketTls13(PskSet pskSet, List<SessionSecret> sessionSecrets) {
        this.pskSet =
                new PskSet(
                        pskSet.getPreSharedKeyIdentity(),
                        pskSet.getPreSharedKey(),
                        pskSet.getTicketAge(),
                        pskSet.getTicketAgeAdd(),
                        pskSet.getTicketNonce(),
                        pskSet.getCipherSuite());
        this.sessionSecrets = sessionSecrets;
    }

    /**
     * Copy constructor for creating a new TLS 1.3 ticket from an existing one.
     *
     * @param toCopy The TLS 1.3 ticket to copy
     */
    public TicketTls13(TicketTls13 toCopy) {
        this(toCopy.pskSet, toCopy.sessionSecrets);
    }

    /**
     * Applies this ticket to the provided TLS configuration.
     *
     * @param config The TLS configuration to modify
     */
    @Override
    public void applyTo(Config config) {
        config.setAddPreSharedKeyExtension(true);

        config.setEarlyDataPsk(pskSet.getPreSharedKey());
        config.setEarlyDataCipherSuite(pskSet.getCipherSuite());

        config.setPsk(pskSet.getPreSharedKey());
        config.setDefaultPSKIdentity(pskSet.getPreSharedKeyIdentity());
        config.setDefaultPskSets(Arrays.asList(pskSet));
    }

    /**
     * Sets the ticket bytes by updating the pre-shared key identity.
     *
     * @param ticketBytes The new ticket bytes to set
     */
    @Override
    public void setTicketBytes(byte[] ticketBytes) {
        pskSet.setPreSharedKeyIdentity(ticketBytes);
    }

    /**
     * Gets the original ticket bytes from the pre-shared key identity.
     *
     * @return The original ticket bytes
     */
    @Override
    public byte[] getTicketBytesOriginal() {
        return pskSet.getPreSharedKeyIdentity();
    }

    /**
     * Creates a copy of this TLS 1.3 ticket.
     *
     * @return A new TicketTls13 instance with the same values
     */
    @Override
    public Ticket copy() {
        return new TicketTls13(this);
    }

    /**
     * Gets the list of session secrets associated with this ticket.
     *
     * @return The list of session secrets
     */
    @Override
    public List<SessionSecret> getSessionSecrets() {
        return sessionSecrets;
    }

    /**
     * Returns a string representation of this ticket as a hex string.
     *
     * @return Hex string representation of the pre-shared key identity
     */
    @Override
    public String toString() {
        return DataConverter.bytesToHexString(pskSet.getPreSharedKeyIdentity(), false, false);
    }
}
