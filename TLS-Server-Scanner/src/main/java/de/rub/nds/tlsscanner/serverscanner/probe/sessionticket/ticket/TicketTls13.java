/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.math3.util.Pair;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.PossibleSecret;

public class TicketTls13 implements Ticket {
    private PskSet pskSet;
    private List<PossibleSecret> possibleSecrets;

    public TicketTls13(PskSet pskSet, List<PossibleSecret> possibleSecrets) {
        this.pskSet = new PskSet(pskSet.getPreSharedKeyIdentity(), pskSet.getPreSharedKey(), pskSet.getTicketAge(),
            pskSet.getTicketAgeAdd(), pskSet.getTicketNonce(), pskSet.getCipherSuite());
        this.possibleSecrets = possibleSecrets;
    }

    public TicketTls13(TicketTls13 toCopy) {
        this(toCopy.pskSet, toCopy.possibleSecrets);
    }

    @Override
    public void applyTo(Config config) {
        config.setAddPreSharedKeyExtension(true);

        config.setEarlyDataPsk(pskSet.getPreSharedKey());
        config.setEarlyDataCipherSuite(pskSet.getCipherSuite());

        config.setPsk(pskSet.getPreSharedKey());
        config.setDefaultPSKIdentity(pskSet.getPreSharedKeyIdentity());
        config.setDefaultPskSets(Arrays.asList(pskSet));
    }

    @Override
    public void setTicketBytes(byte[] ticketBytes) {
        pskSet.setPreSharedKeyIdentity(ticketBytes);
    }

    @Override
    public byte[] getTicketBytesOriginal() {
        return pskSet.getPreSharedKeyIdentity();
    }

    @Override
    public Ticket copy() {
        return new TicketTls13(this);
    }

    @Override
    public List<PossibleSecret> getPossibleSecrets() {
        return possibleSecrets;
    }

    @Override
    public String toString() {
        return ArrayConverter.bytesToHexString(pskSet.getPreSharedKeyIdentity(), false, false);
    }
}
