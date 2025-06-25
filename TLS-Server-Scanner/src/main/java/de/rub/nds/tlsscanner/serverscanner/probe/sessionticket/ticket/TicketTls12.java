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
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionSecret;
import java.util.List;

public class TicketTls12 implements Ticket {

    private byte[] ticketBytes;
    private byte[] masterSecret;
    private List<SessionSecret> sessionSecrets;

    @SuppressWarnings("unused")
    // This constructor is used by Jackson for deserialization
    private TicketTls12() {
        this.ticketBytes = null;
        this.masterSecret = null;
        this.sessionSecrets = List.of();
    }

    /**
     * Constructs a new TLS 1.2 (and below) ticket with the specified ticket bytes, master secret,
     * and session secrets.
     *
     * @param ticketBytes The ticket bytes
     * @param masterSecret The master secret associated with this ticket
     * @param sessionSecrets List of session secrets associated with this ticket
     */
    public TicketTls12(
            byte[] ticketBytes, byte[] masterSecret, List<SessionSecret> sessionSecrets) {
        this.ticketBytes = ticketBytes;
        this.masterSecret = masterSecret;
        this.sessionSecrets = sessionSecrets;
    }

    /**
     * Copy constructor for creating a new TLS 1.2 (and below) ticket from an existing one.
     *
     * @param toCopy The TLS 1.2 (and below) ticket to copy
     */
    public TicketTls12(TicketTls12 toCopy) {
        this(toCopy.ticketBytes, toCopy.masterSecret, toCopy.sessionSecrets);
    }

    /**
     * Applies this ticket to the provided TLS configuration.
     *
     * @param config The TLS configuration to modify
     */
    @Override
    public void applyTo(Config config) {
        config.setTlsSessionTicket(ticketBytes);
        config.setDefaultMasterSecret(masterSecret);
    }

    /**
     * Sets the ticket bytes.
     *
     * @param ticketBytes The new ticket bytes to set
     */
    @Override
    public void setTicketBytes(byte[] ticketBytes) {
        this.ticketBytes = ticketBytes;
    }

    /**
     * Gets the original ticket bytes.
     *
     * @return The original ticket bytes
     */
    @Override
    public byte[] getTicketBytesOriginal() {
        return ticketBytes;
    }

    /**
     * Creates a copy of this TLS 1.2 (and below) ticket.
     *
     * @return A new TicketTls12 instance with the same values
     */
    @Override
    public Ticket copy() {
        return new TicketTls12(this);
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
     * @return Hex string representation of the ticket bytes
     */
    @Override
    public String toString() {
        return DataConverter.bytesToHexString(ticketBytes, false, false);
    }
}
