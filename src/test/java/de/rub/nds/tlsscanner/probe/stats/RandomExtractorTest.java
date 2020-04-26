/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.stats;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.state.State;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import java.util.Random;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Test-Class for RandomExtractor.java, which currently looks for the
 * serverHello-message of the TLS-Handshake and extracts the random-bytes
 * transmitted
 *
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class RandomExtractorTest {

    /**
     * Note: For each test-method, junit will create a new instance of
     * "RandomExtractorTest". This means that there are no potential
     * race-conditions when defining class-variables, which are modified in
     * separate methods, even when running tests in parallel.
     */
    private WorkflowTrace testTrace;
    private RandomExtractor extractor;
    private final Logger LOGGER = LogManager.getLogger();
    private final byte[] GENERATED_RANDOM;
    private final static byte[] STATIC_RANDOM = new byte[] { 0, 1, 2, 3, 4, 5 };
    private final SendAction TEST_CLIENT_HELLO;

    /**
     * We use the constructor instead of Junit @Before to initialize final
     * variables.
     */
    public RandomExtractorTest() {
        // Generic ClientHello to populate WorkflowTrace
        TEST_CLIENT_HELLO = new SendAction();
        ClientHelloMessage msgClient = new ClientHelloMessage();
        msgClient.setRandom(STATIC_RANDOM.clone());
        TEST_CLIENT_HELLO.setMessages(msgClient);

        testTrace = new WorkflowTrace();
        extractor = new RandomExtractor();

        GENERATED_RANDOM = new byte[32];
        new Random().nextBytes(GENERATED_RANDOM);

    }

    /**
     * Helper Method for generating serverHello-Messages
     * 
     * @param rndBytes
     *            the random-bytes of the serverHello Message
     * @return serverHello Message with the random-bytes set.
     */
    private ReceiveAction generateServerHello(byte[] rndBytes) {
        ReceiveAction testServerHello = new ReceiveAction();
        ServerHelloMessage msg = new ServerHelloMessage();
        msg.setRandom(rndBytes);
        testServerHello.setMessages(msg);
        return testServerHello;
    }

    /**
     * Testing extraction of a "valid" ServerHello-Message
     */
    @Test
    public void testValidExtract() {
        testTrace.addTlsAction(TEST_CLIENT_HELLO);

        // Use clone to set new object as message-random instead of the
        // reference to random_bytes
        ReceiveAction testServerHello = generateServerHello(GENERATED_RANDOM.clone());

        testTrace.addTlsAction(testServerHello);

        State state = new State(testTrace);
        extractor.extract(state);

        ComparableByteArray generatedRandom = new ComparableByteArray(GENERATED_RANDOM);
        ComparableByteArray extractedRandom = extractor.getContainer().getExtractedValueList().get(0);

        // Make sure that only ServerHello random-bytes are extracted
        assertEquals(1, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(generatedRandom, extractedRandom);
    }

    /**
     * Testing handshake-message without ServerHello
     */
    @Test(expected = IndexOutOfBoundsException.class)
    public void testNoServerHelloExtract() {
        testTrace.addTlsAction(TEST_CLIENT_HELLO);

        // Additionally check if a serverHello as a Send-Action is
        // ignored by RandomExtractor
        SendAction testServerHello = new SendAction();
        ServerHelloMessage msg = new ServerHelloMessage();
        msg.setRandom(GENERATED_RANDOM.clone());
        testTrace.addTlsAction(testServerHello);

        State state = new State(testTrace);
        extractor.extract(state);

        assertEquals(0, extractor.getContainer().getExtractedValueList().size());
        assertEquals(0, extractor.getContainer().getNumberOfExtractedValues());
        extractor.getContainer().getExtractedValueList().get(0);
        // If there is no exception thrown here, then there is a value saved in
        // the value-list. This should fail
        // the test.
        fail();
    }

    /**
     * Testing empty WorkflowTrace. Expecting an out of bound exception when
     * trying to access the first element of the empty value-container
     */
    @Test(expected = IndexOutOfBoundsException.class)
    public void testEmptyWorkflowTraceExtract() {
        State state = new State(testTrace);

        extractor.extract(state);

        assertEquals(0, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(0, extractor.getContainer().getExtractedValueList().size());
        extractor.getContainer().getExtractedValueList().get(0);
        // If there is no exception thrown here, then there is a value saved in
        // the value-list. This should fail
        // the test.
        fail();
    }

    @Test
    public void testBigRandomBytesExtract() {
        // 120 random-bytes should be much more than you would see in the wild
        byte[] b = new byte[120];
        new Random().nextBytes(b);

        ReceiveAction testServerHello = generateServerHello(b.clone());

        testTrace.addTlsAction(testServerHello);
        State state = new State(testTrace);

        ComparableByteArray generatedRandom = new ComparableByteArray(b);

        extractor.extract(state);
        assertEquals(1, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(generatedRandom, extractor.getContainer().getExtractedValueList().get(0));
    }

    @Test
    public void testMultipleServerHelloExtract() {
        testTrace.addTlsAction(TEST_CLIENT_HELLO);

        ComparableByteArray generatedRandom1 = new ComparableByteArray(GENERATED_RANDOM);
        ComparableByteArray generatedRandom2 = new ComparableByteArray(STATIC_RANDOM);

        ReceiveAction testServerHello1 = generateServerHello(GENERATED_RANDOM.clone());
        ReceiveAction testServerHello2 = generateServerHello(STATIC_RANDOM.clone());
        ReceiveAction testServerHello3 = generateServerHello(GENERATED_RANDOM.clone());

        testTrace.addTlsAction(testServerHello1);
        testTrace.addTlsAction(testServerHello2);
        testTrace.addTlsAction(testServerHello3);

        State state = new State(testTrace);

        extractor.extract(state);

        ComparableByteArray extractedRandom1 = extractor.getContainer().getExtractedValueList().get(0);
        ComparableByteArray extractedRandom2 = extractor.getContainer().getExtractedValueList().get(1);
        ComparableByteArray extractedRandom3 = extractor.getContainer().getExtractedValueList().get(2);

        assertEquals(3, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(generatedRandom1, extractedRandom1);
        assertEquals(generatedRandom2, extractedRandom2);
        assertEquals(extractedRandom1, extractedRandom3);
    }

    /**
     * Check if values are extracted correctly by checking if all values are
     * equal
     */
    @Test
    public void testEqualRandomNumbers() {
        testTrace.addTlsAction(TEST_CLIENT_HELLO);

        ReceiveAction testServerHello1 = generateServerHello(GENERATED_RANDOM.clone());
        ReceiveAction testServerHello2 = generateServerHello(GENERATED_RANDOM.clone());

        testTrace.addTlsAction(testServerHello1);
        testTrace.addTlsAction(testServerHello2);

        State state = new State(testTrace);

        extractor.extract(state);

        assertTrue(extractor.getContainer().areAllValuesIdentical());
    }

    /***
     * Testing a mix of valid and invalid ServerHello-Messages inside the
     * WorkflowTrace.
     */
    @Test
    public void testValidEmptyMixExtract() {
        testTrace.addTlsAction(TEST_CLIENT_HELLO);

        ReceiveAction testServerHello1 = generateServerHello(GENERATED_RANDOM.clone());
        ReceiveAction testServerHello3 = generateServerHello(GENERATED_RANDOM.clone());

        // ServerHello without random-bytes
        ReceiveAction testServerHello2 = new ReceiveAction();
        ServerHelloMessage msg = new ServerHelloMessage();
        testServerHello2.setMessages(msg);

        testTrace.addTlsAction(testServerHello1);
        testTrace.addTlsAction(testServerHello2);
        testTrace.addTlsAction(testServerHello3);

        State state = new State(testTrace);

        try {
            extractor.extract(state);
            assertEquals(2, extractor.getContainer().getNumberOfExtractedValues());
        } catch (NullPointerException ex) {
            LOGGER.warn("RandomExtractor encountered Problems handling ServerHello without random-bytes.");
            // fail(); Commented out - Remove this comment when the
            // RandomExtractor or StatExtractor correctly handles
            // missing expected values.
        }

    }

    /**
     * Testing a WorkflowTrace with an invalid ServerHello-Message.
     */
    @Test
    public void testNoRandomExtract() {
        testTrace.addTlsAction(TEST_CLIENT_HELLO);

        // ServerHello without random-bytes
        ReceiveAction testServerHello = new ReceiveAction();
        ServerHelloMessage msg = new ServerHelloMessage();
        testServerHello.setMessages(msg);

        testTrace.addTlsAction(testServerHello);
        State state = new State(testTrace);

        try {
            extractor.extract(state);
            assertEquals(0, extractor.getContainer().getExtractedValueList().size());
        } catch (NullPointerException ex) {
            LOGGER.warn("RandomExtractor encountered Problems handling ServerHello without random-bytes.");
            // fail(); Commented out - Remove this comment when the
            // RandomExtractor or StatExtractor correctly handles
            // missing expected values.
        }

    }

}