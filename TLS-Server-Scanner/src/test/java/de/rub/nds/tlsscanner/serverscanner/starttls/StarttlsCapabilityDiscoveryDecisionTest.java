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
import org.junit.jupiter.api.Test;

public class StarttlsCapabilityDiscoveryDecisionTest {

    /** FTP is the only protocol the longer upgrade is defined for so far. */
    @Test
    public void testOnlyFtpIsRetried() {
        String badSequence = "503 Bad sequence of commands\r\n";
        assertTrue(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.FTP, badSequence));
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.IMAP, badSequence));
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.NONE, badSequence));
    }

    @Test
    public void testBadSequenceRefusalIsRetried() {
        assertTrue(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.FTP, "503 Bad sequence of commands\r\n"));
    }

    @Test
    public void testOtherRefusalsAreNotRetried() {
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.FTP, "502 Command not implemented\r\n"));
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.FTP, "500 Syntax error\r\n"));
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.FTP, "530 Not logged in\r\n"));
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.FTP, "534 Request denied for policy reasons\r\n"));
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.FTP, "421 Service not available\r\n"));
    }

    @Test
    public void testMissingOrSuccessfulReplyIsNotRetried() {
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.FTP, null));
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(StarttlsType.FTP, ""));
        assertFalse(
                StarttlsCapabilityDiscoveryDecision.shouldRetryWithDiscovery(
                        StarttlsType.FTP, "234 AUTH TLS OK.\r\n"));
    }

    @Test
    public void testUpgradeReplyIsReadFromTheLastPrefixAction() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new ReceiveRegexTextAction("^220 "));
        trace.addTlsAction(new SendTextAction("AUTH TLS\r\n", null));
        trace.addTlsAction(new ReceiveRegexTextAction("^234 "));

        // Nothing was received because the trace was never executed.
        assertNull(StarttlsCapabilityDiscoveryDecision.getMinimalUpgradeReply(trace));
        assertNull(StarttlsCapabilityDiscoveryDecision.getMinimalUpgradeReply(new WorkflowTrace()));
    }
}
