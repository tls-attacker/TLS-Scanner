/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.stats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.scanner.core.util.ComparableByteArray;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.core.passive.RandomExtractor;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Test-Class for RandomExtractor.java, which currently looks for the serverHello-message of the
 * TLS-Handshake and extracts the random-bytes transmitted.
 */
public class RandomExtractorTest {

    private WorkflowTrace testTrace;
    private RandomExtractor extractor;

    @SuppressWarnings("SpellCheckingInspection")
    private static final byte[] STATIC_RANDOM1 =
            ArrayConverter.hexStringToByteArray(
                    "4DDE56987D18EF88F94030A808800DC680BBFD3B9D6B9B522E8339053DC2EDEE");

    @SuppressWarnings("SpellCheckingInspection")
    private static final byte[] STATIC_RANDOM2 =
            ArrayConverter.hexStringToByteArray(
                    "CC4DC97612BDB5DA500D45B69B9F4FD8D1B449AD9FDD509DA7DC95F8077CDA7B");

    @SuppressWarnings("SpellCheckingInspection")
    private static final byte[] LONG_STATIC_RANDOM3 =
            ArrayConverter.hexStringToByteArray(
                    "19C26C4DD15B39"
                            + "C49DFF3EAFB83130E8FAA462F252C2E0ED7F389ECC349A38DA1DB5D3E8D04BA6D77E6B05E81B04CF41CF737CC44E"
                            + "F614E2B05672A18BE97E94345A112186A15529B05918CE3662D4DD18B909C161AA76AF7192CA6D20E074788E0059"
                            + "42DD3C46FBCB6C7C2D620B2AF65E98A8C06BEBA0FF");

    private SendAction testClientHello;

    /**
     * Helper Method for generating serverHello-Messages
     *
     * @param rndBytes the random-bytes of the serverHello Message
     * @return serverHello Message with the random-bytes set.
     */
    private ReceiveAction generateServerHello(byte[] rndBytes) {
        ReceiveAction testServerHello = Mockito.mock(ReceiveAction.class);
        ServerHelloMessage msg = new ServerHelloMessage();
        msg.setRandom(rndBytes);
        testServerHello.setExpectedMessages(msg);
        Mockito.when(testServerHello.getReceivedMessages()).thenReturn(List.of(msg));

        return testServerHello;
    }

    /**
     * Setting up a test ClientHello-message for filtering and an empty WorkflowTrace for filling it
     * with the generated ServerHello-messages and an fresh extractor.
     */
    @BeforeEach
    public void setUp() {
        testClientHello = new SendAction();
        ClientHelloMessage msgClient = new ClientHelloMessage();
        msgClient.setRandom(STATIC_RANDOM1.clone());
        testClientHello.setConfiguredMessages(msgClient);

        testTrace = new WorkflowTrace();
        extractor = new RandomExtractor();
    }

    /** Testing extraction of a "valid" ServerHello-Message */
    @Test
    public void testValidExtract() {
        testTrace.addTlsAction(testClientHello);

        // Use clone to set new object as message-random instead of the
        // reference to random_bytes
        ReceiveAction testServerHello = generateServerHello(STATIC_RANDOM1.clone());

        testTrace.addTlsAction(testServerHello);

        State state = new State(testTrace);
        extractor.extract(state);

        ComparableByteArray generatedRandom = new ComparableByteArray(STATIC_RANDOM1);
        ComparableByteArray extractedRandom =
                extractor.getContainer().getExtractedValueList().get(0);

        // Make sure that only ServerHello random-bytes are extracted
        assertEquals(1, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(generatedRandom, extractedRandom);
    }

    /** Testing handshake-message without ServerHello */
    @Test
    public void testNoServerHelloExtract() {
        testTrace.addTlsAction(testClientHello);

        // Additionally check if a serverHello as a Send-Action is
        // ignored by RandomExtractor
        SendAction testServerHello = new SendAction();
        ServerHelloMessage msg = new ServerHelloMessage();
        msg.setRandom(STATIC_RANDOM1.clone());
        testTrace.addTlsAction(testServerHello);

        State state = new State(testTrace);
        extractor.extract(state);

        assertEquals(0, extractor.getContainer().getExtractedValueList().size());
        assertEquals(0, extractor.getContainer().getNumberOfExtractedValues());
        assertTrue(extractor.getContainer().getExtractedValueList().isEmpty());
    }

    /** Testing empty WorkflowTrace. */
    @Test
    public void testEmptyWorkflowTraceExtract() {
        State state = new State(testTrace);

        extractor.extract(state);

        assertEquals(0, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(0, extractor.getContainer().getExtractedValueList().size());
        assertTrue(extractor.getContainer().getExtractedValueList().isEmpty());
    }

    @Test
    public void testBigRandomBytesExtract() {
        ReceiveAction testServerHello = generateServerHello(LONG_STATIC_RANDOM3.clone());

        testTrace.addTlsAction(testServerHello);
        State state = new State(testTrace);

        ComparableByteArray generatedRandom = new ComparableByteArray(LONG_STATIC_RANDOM3);

        extractor.extract(state);
        assertEquals(1, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(generatedRandom, extractor.getContainer().getExtractedValueList().get(0));
    }

    @Test
    public void testMultipleServerHelloExtract() {
        testTrace.addTlsAction(testClientHello);

        ComparableByteArray generatedRandom1 = new ComparableByteArray(STATIC_RANDOM1);
        ComparableByteArray generatedRandom2 = new ComparableByteArray(STATIC_RANDOM2);

        ReceiveAction testServerHello1 = generateServerHello(STATIC_RANDOM1.clone());
        ReceiveAction testServerHello2 = generateServerHello(STATIC_RANDOM2.clone());
        ReceiveAction testServerHello3 = generateServerHello(STATIC_RANDOM1.clone());

        testTrace.addTlsAction(testServerHello1);
        testTrace.addTlsAction(testServerHello2);
        testTrace.addTlsAction(testServerHello3);

        State state = new State(testTrace);

        extractor.extract(state);

        ComparableByteArray extractedRandom1 =
                extractor.getContainer().getExtractedValueList().get(0);
        ComparableByteArray extractedRandom2 =
                extractor.getContainer().getExtractedValueList().get(1);
        ComparableByteArray extractedRandom3 =
                extractor.getContainer().getExtractedValueList().get(2);

        assertEquals(3, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(generatedRandom1, extractedRandom1);
        assertEquals(generatedRandom2, extractedRandom2);
        assertEquals(extractedRandom1, extractedRandom3);
    }

    /** Check if values are extracted correctly by checking if all values are equal */
    @Test
    public void testEqualRandomNumbers() {
        testTrace.addTlsAction(testClientHello);

        ReceiveAction testServerHello1 = generateServerHello(STATIC_RANDOM1.clone());
        ReceiveAction testServerHello2 = generateServerHello(STATIC_RANDOM1.clone());

        testTrace.addTlsAction(testServerHello1);
        testTrace.addTlsAction(testServerHello2);

        State state = new State(testTrace);

        extractor.extract(state);

        assertTrue(extractor.getContainer().areAllValuesIdentical());
    }

    /***
     * Testing a mix of valid and invalid ServerHello-Messages inside the WorkflowTrace.
     */
    @Test
    public void testValidEmptyMixExtract() {
        testTrace.addTlsAction(testClientHello);

        ReceiveAction testServerHello1 = generateServerHello(STATIC_RANDOM1.clone());
        ReceiveAction testServerHello3 = generateServerHello(STATIC_RANDOM1.clone());

        // ServerHello without random-bytes
        ReceiveAction testServerHello2 = new ReceiveAction();
        ServerHelloMessage msg = new ServerHelloMessage();
        testServerHello2.setExpectedMessages(msg);

        testTrace.addTlsAction(testServerHello1);
        testTrace.addTlsAction(testServerHello2);
        testTrace.addTlsAction(testServerHello3);

        State state = new State(testTrace);

        extractor.extract(state);
        assertEquals(4, state.getWorkflowTrace().getTlsActions().size());
        assertEquals(2, extractor.getContainer().getNumberOfExtractedValues());
    }

    /** Testing a WorkflowTrace with an invalid ServerHello-Message. */
    @Test
    public void testNoRandomExtract() {
        testTrace.addTlsAction(testClientHello);

        // ServerHello without random-bytes
        ReceiveAction testServerHello = new ReceiveAction();
        ServerHelloMessage msg = new ServerHelloMessage();
        testServerHello.setExpectedMessages(msg);

        testTrace.addTlsAction(testServerHello);
        State state = new State(testTrace);

        extractor.extract(state);
        assertEquals(0, extractor.getContainer().getExtractedValueList().size());
        assertTrue(extractor.getContainer().getExtractedValueList().isEmpty());
    }
}
