/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.FoundSecret;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionSecret;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionSecret.Secret;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class TicketTest {

    @Test
    void testCheckContainsSecretsWithNullHaystack() {
        Ticket ticket =
                new TestTicket(
                        Arrays.asList(
                                new SessionSecret(Secret.MASTER_SECRET, new byte[] {1, 2, 3})));

        FoundSecret result = ticket.checkContainsSecrets(null);
        assertNull(result);
    }

    @Test
    void testCheckContainsSecretsWithEmptyHaystack() {
        Ticket ticket =
                new TestTicket(
                        Arrays.asList(
                                new SessionSecret(Secret.MASTER_SECRET, new byte[] {1, 2, 3})));

        FoundSecret result = ticket.checkContainsSecrets(new byte[] {});
        assertNull(result);
    }

    @Test
    void testCheckContainsSecretsWithNullSessionSecrets() {
        Ticket ticket = new TestTicket(null);

        FoundSecret result = ticket.checkContainsSecrets(new byte[] {1, 2, 3});
        assertNull(result);
    }

    @Test
    void testCheckContainsSecretsFoundSecret() {
        byte[] secret = new byte[] {3, 4, 5};
        Ticket ticket =
                new TestTicket(Arrays.asList(new SessionSecret(Secret.MASTER_SECRET, secret)));

        byte[] haystack = new byte[] {1, 2, 3, 4, 5, 6};
        FoundSecret result = ticket.checkContainsSecrets(haystack);

        assertNotNull(result);
        assertEquals(Secret.MASTER_SECRET, result.secret.secretType);
        assertEquals(2, result.offset);
    }

    @Test
    void testCheckContainsSecretsNotFound() {
        Ticket ticket =
                new TestTicket(
                        Arrays.asList(
                                new SessionSecret(Secret.MASTER_SECRET, new byte[] {7, 8, 9})));

        byte[] haystack = new byte[] {1, 2, 3, 4, 5, 6};
        FoundSecret result = ticket.checkContainsSecrets(haystack);

        assertNull(result);
    }

    private static class TestTicket implements Ticket {
        private final List<SessionSecret> sessionSecrets;

        public TestTicket(List<SessionSecret> sessionSecrets) {
            this.sessionSecrets = sessionSecrets;
        }

        @Override
        public void applyTo(de.rub.nds.tlsattacker.core.config.Config config) {}

        @Override
        public void setTicketBytes(byte[] ticketBytes) {}

        @Override
        public byte[] getTicketBytesOriginal() {
            return new byte[] {};
        }

        @Override
        public Ticket copy() {
            return new TestTicket(sessionSecrets);
        }

        @Override
        public List<SessionSecret> getSessionSecrets() {
            return sessionSecrets;
        }
    }
}
