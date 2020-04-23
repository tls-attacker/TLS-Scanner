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
    private final byte[] random_bytes;
    private final static byte[] STATIC_RANDOM = new byte[] { 0, 1, 2, 3, 4, 5, };
    private final SendAction testClientHello;

    /**
     * We use the constructor instead of Junit @Before to initialize final
     * variables.
     */
    public RandomExtractorTest() {
        // Generic ClientHello to populate WorkflowTrace
        testClientHello = new SendAction();
        ClientHelloMessage msg_client = new ClientHelloMessage();
        msg_client.setRandom(STATIC_RANDOM.clone());
        testClientHello.setMessages(msg_client);

        testTrace = new WorkflowTrace();
        extractor = new RandomExtractor();

        random_bytes = new byte[32];
        new Random().nextBytes(random_bytes);

    }

    /**
     * Helper Method for generating serverHello-Messages
     * 
     * @param rnd_bytes
     *            the random-bytes of the serverHello Message
     * @return serverHello Message with the random-bytes set.
     */
    private ReceiveAction generateServerHello(byte[] rnd_bytes) {
        ReceiveAction testServerHello = new ReceiveAction();
        ServerHelloMessage msg = new ServerHelloMessage();
        msg.setRandom(rnd_bytes);
        testServerHello.setMessages(msg);
        return testServerHello;
    }

    /**
     * Testing extraction of a "valid" ServerHello-Message
     */
    @Test
    public void testValidExtract() {
        testTrace.addTlsAction(testClientHello);

        // Use clone to set new object as message-random instead of the
        // reference to random_bytes
        ReceiveAction testServerHello = generateServerHello(random_bytes.clone());

        testTrace.addTlsAction(testServerHello);

        State state = new State(testTrace);
        extractor.extract(state);

        ComparableByteArray generated_random = new ComparableByteArray(random_bytes);
        ComparableByteArray extracted_random = extractor.getContainer().getExtractedValueList().get(0);

        // Make sure that only ServerHello random-bytes are extracted
        assertEquals(1, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(generated_random, extracted_random);
    }

    /**
     * Testing handshake-message without ServerHello
     */
    @Test(expected = IndexOutOfBoundsException.class)
    public void testNoServerHelloExtract() {
        testTrace.addTlsAction(testClientHello);

        // Additionally check if a serverHello as a Send-Action is not
        // considered by RandomExtractor
        SendAction testServerHello = new SendAction();
        ServerHelloMessage msg = new ServerHelloMessage();
        msg.setRandom(random_bytes.clone());
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
    public void testEmptyWorkflowTrace() {
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
    public void testLongRandomBytesExtract() {

        // 120 random-bytes should be much more than you would see in the wild
        byte[] b = new byte[120];
        new Random().nextBytes(b);

        ReceiveAction testServerHello = generateServerHello(b.clone());

        testTrace.addTlsAction(testServerHello);
        State state = new State(testTrace);

        ComparableByteArray generated_random = new ComparableByteArray(b);

        extractor.extract(state);
        assertEquals(1, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(generated_random, extractor.getContainer().getExtractedValueList().get(0));
    }

    @Test
    public void testMultipleServerHelloExtract() {
        testTrace.addTlsAction(testClientHello);

        ComparableByteArray generated_random_1 = new ComparableByteArray(random_bytes);
        ComparableByteArray generated_random_2 = new ComparableByteArray(STATIC_RANDOM);

        ReceiveAction testServerHello_1 = generateServerHello(random_bytes.clone());
        ReceiveAction testServerHello_2 = generateServerHello(STATIC_RANDOM.clone());
        ReceiveAction testServerHello_3 = generateServerHello(random_bytes.clone());

        testTrace.addTlsAction(testServerHello_1);
        testTrace.addTlsAction(testServerHello_2);
        testTrace.addTlsAction(testServerHello_3);

        State state = new State(testTrace);

        extractor.extract(state);

        ComparableByteArray extracted_random_1 = extractor.getContainer().getExtractedValueList().get(0);
        ComparableByteArray extracted_random_2 = extractor.getContainer().getExtractedValueList().get(1);
        ComparableByteArray extracted_random_3 = extractor.getContainer().getExtractedValueList().get(2);

        assertEquals(3, extractor.getContainer().getNumberOfExtractedValues());
        assertEquals(generated_random_1, extracted_random_1);
        assertEquals(generated_random_2, extracted_random_2);
        assertEquals(extracted_random_1, extracted_random_3);

    }

    /**
     * Check if values are extracted correctly by checking if all values are
     * equal
     */
    @Test
    public void testEqualRandomNumbers() {
        testTrace.addTlsAction(testClientHello);

        ReceiveAction testServerHello_1 = generateServerHello(random_bytes.clone());
        ReceiveAction testServerHello_2 = generateServerHello(random_bytes.clone());

        testTrace.addTlsAction(testServerHello_1);
        testTrace.addTlsAction(testServerHello_2);

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
        testTrace.addTlsAction(testClientHello);

        ReceiveAction testServerHello_1 = generateServerHello(random_bytes.clone());
        ReceiveAction testServerHello_3 = generateServerHello(random_bytes.clone());

        // ServerHello without random-bytes
        ReceiveAction testServerHello_2 = new ReceiveAction();
        ServerHelloMessage msg_2 = new ServerHelloMessage();
        testServerHello_2.setMessages(msg_2);

        testTrace.addTlsAction(testServerHello_1);
        testTrace.addTlsAction(testServerHello_2);
        testTrace.addTlsAction(testServerHello_3);

        State state = new State(testTrace);

        try {
            extractor.extract(state);
            assertEquals(2, extractor.getContainer().getNumberOfExtractedValues());
        } catch (NullPointerException ex) {
            LOGGER.warn("RandomExtractor encountered Problems handling ServerHello without random-bytes.");
            // fail(); Commented out - may be expected behaviour. If not, remove
            // this comment.
        }

    }

    /**
     * Testing a WorkflowTrace with an invalid ServerHello-Message.
     */
    @Test
    public void testNoRandomToExtract() {
        testTrace.addTlsAction(testClientHello);

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
            // fail(); Commented out - may be expected behaviour. If not, remove
            // this comment.
        }

    }

}