/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.starttls;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveRegexTextAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendTextAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.List;
import org.junit.jupiter.api.Test;

public class StarttlsCapabilityDiscoveryTest {

    /** FTP is the only protocol with a discovery exchange so far; the rest must report none. */
    @Test
    public void testLookupByStarttlsType() {
        assertEquals(
                StarttlsCapabilityDiscovery.FTP,
                StarttlsCapabilityDiscovery.forType(StarttlsType.FTP));
        assertNull(StarttlsCapabilityDiscovery.forType(StarttlsType.IMAP));
        assertNull(StarttlsCapabilityDiscovery.forType(StarttlsType.NONE));
    }

    /** The FTP exchange is the RFC 4217 sequence: greeting, FEAT, feature list, AUTH TLS, 234. */
    @Test
    public void testFtpExchangeIsPrependedInOrder() {
        WorkflowTrace trace = new WorkflowTrace();
        StarttlsCapabilityDiscovery.FTP.prependTo(trace);

        List<TlsAction> actions = trace.getTlsActions();
        assertEquals(StarttlsCapabilityDiscovery.FTP.getActionCount(), actions.size());
        assertEquals("^220 ", ((ReceiveRegexTextAction) actions.get(0)).getRegex());
        assertEquals("FEAT\r\n", ((SendTextAction) actions.get(1)).getText());
        assertEquals("^211 ", ((ReceiveRegexTextAction) actions.get(2)).getRegex());
        assertEquals("AUTH TLS\r\n", ((SendTextAction) actions.get(3)).getText());
        assertEquals("^234 ", ((ReceiveRegexTextAction) actions.get(4)).getRegex());
    }

    /** Both replies must abort on a 4xx/5xx, so a refusal ends the trace instead of hanging. */
    @Test
    public void testRepliesAbortOnErrorStatus() {
        WorkflowTrace trace = new WorkflowTrace();
        StarttlsCapabilityDiscovery.FTP.prependTo(trace);

        List<TlsAction> actions = trace.getTlsActions();
        assertEquals("^[45]\\d\\d ", ((ReceiveRegexTextAction) actions.get(2)).getAbortRegex());
        assertEquals("^[45]\\d\\d ", ((ReceiveRegexTextAction) actions.get(4)).getAbortRegex());
    }

    /** The exchange is prepended, so an existing handshake trace keeps its actions and order. */
    @Test
    public void testExistingActionsAreKeptAfterTheExchange() {
        WorkflowTrace trace = new WorkflowTrace();
        SendTextAction existing = new SendTextAction("existing\r\n", null);
        trace.addTlsAction(existing);
        StarttlsCapabilityDiscovery.FTP.prependTo(trace);

        List<TlsAction> actions = trace.getTlsActions();
        assertEquals(StarttlsCapabilityDiscovery.FTP.getActionCount() + 1, actions.size());
        assertSame(existing, actions.get(actions.size() - 1));
    }

    /**
     * A refusal that blames where the command appeared is worth a second attempt: 503 is the
     * sequence error a server sends when it wants FEAT first, 530 wants a login, 421 is a temporary
     * unavailability.
     */
    @Test
    public void testSequenceRefusalsAreRetried() {
        assertTrue(
                StarttlsCapabilityDiscovery.FTP.isRetryableRefusal(
                        "534 Send FEAT first: capability discovery required before AUTH\r\n"));
        assertTrue(
                StarttlsCapabilityDiscovery.FTP.isRetryableRefusal(
                        "431 Security mechanism unavailable\r\n"));
        assertTrue(
                StarttlsCapabilityDiscovery.FTP.isRetryableRefusal(
                        "503 Bad sequence of commands\r\n"));
        assertTrue(StarttlsCapabilityDiscovery.FTP.isRetryableRefusal("530 Not logged in\r\n"));
        assertTrue(
                StarttlsCapabilityDiscovery.FTP.isRetryableRefusal(
                        "421 Service not available\r\n"));
    }

    /**
     * A server that does not implement the upgrade answers the same way however it is reached, so
     * the capability exchange would only cost a connection.
     */
    @Test
    public void testUnsupportedCommandRefusalsAreNotRetried() {
        assertFalse(
                StarttlsCapabilityDiscovery.FTP.isRetryableRefusal(
                        "502 Command not implemented\r\n"));
        assertFalse(StarttlsCapabilityDiscovery.FTP.isRetryableRefusal("500 Syntax error\r\n"));
        assertFalse(
                StarttlsCapabilityDiscovery.FTP.isRetryableRefusal(
                        "504 Command not implemented for that parameter\r\n"));
    }

    /** No reply is no evidence that discovery would help, so it must not trigger a retry. */
    @Test
    public void testMissingOrUnusableReplyIsNotRetried() {
        assertFalse(StarttlsCapabilityDiscovery.FTP.isRetryableRefusal(null));
        assertFalse(StarttlsCapabilityDiscovery.FTP.isRetryableRefusal(""));
        assertFalse(StarttlsCapabilityDiscovery.FTP.isRetryableRefusal("50"));
        assertFalse(StarttlsCapabilityDiscovery.FTP.isRetryableRefusal("234 Proceed\r\n"));
    }

    /** The upgrade reply is the last action of the minimal prefix TLS-Attacker builds. */
    @Test
    public void testMinimalUpgradeReplyIsReadFromTheLastPrefixAction() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new ReceiveRegexTextAction("^220 "));
        trace.addTlsAction(new SendTextAction("AUTH TLS\r\n", null));
        trace.addTlsAction(new ReceiveRegexTextAction("^234 "));

        assertNull(StarttlsCapabilityDiscovery.getMinimalUpgradeReply(trace, 3));
        assertNull(StarttlsCapabilityDiscovery.getMinimalUpgradeReply(new WorkflowTrace(), 3));
    }
}
