/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsscanner.core.vector.Vector;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class InformationLeakTestTest {

    private static class TestVector implements Vector {
        private final String name;

        public TestVector(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof TestVector) {
                return name.equals(((TestVector) obj).name);
            }
            return false;
        }

        @Override
        public int hashCode() {
            return name.hashCode();
        }
    }

    private static class SimpleTestInfo extends TestInfo {
        @Override
        public String getTechnicalName() {
            return "SimpleTest";
        }

        @Override
        public List<String> getFieldNames() {
            return List.of();
        }

        @Override
        public List<String> getFieldValues() {
            return List.of();
        }

        @Override
        public String getPrintableName() {
            return "Simple Test";
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof SimpleTestInfo;
        }

        @Override
        public int hashCode() {
            return getTechnicalName().hashCode();
        }
    }

    @Test
    public void testGetRareResponsesWithNoResponses() {
        List<VectorResponse> responses = new ArrayList<>();
        InformationLeakTest<SimpleTestInfo> test =
                new InformationLeakTest<>(new SimpleTestInfo(), responses);

        List<VectorResponse> rareResponses = test.getRareResponses(1);
        assertTrue(rareResponses.isEmpty());
    }

    @Test
    public void testGetRareResponsesWithUniqueResponse() {
        List<VectorResponse> responses = new ArrayList<>();
        TestVector vector1 = new TestVector("vector1");
        TestVector vector2 = new TestVector("vector2");
        TestVector vector3 = new TestVector("vector3");

        ResponseFingerprint fingerprint1 =
                new ResponseFingerprint(new ArrayList<>(), new ArrayList<>(), SocketState.CLOSED);
        ResponseFingerprint fingerprint2 =
                new ResponseFingerprint(new ArrayList<>(), new ArrayList<>(), SocketState.TIMEOUT);

        // vector1 and vector2 have fingerprint1, vector3 has unique fingerprint2
        responses.add(new VectorResponse(vector1, fingerprint1));
        responses.add(new VectorResponse(vector2, fingerprint1));
        responses.add(new VectorResponse(vector3, fingerprint2));

        InformationLeakTest<SimpleTestInfo> test =
                new InformationLeakTest<>(new SimpleTestInfo(), responses);

        // Get responses that occurred at most once
        List<VectorResponse> rareResponses = test.getRareResponses(1);
        assertEquals(1, rareResponses.size());
        assertEquals(vector3, rareResponses.get(0).getVector());
        assertEquals(fingerprint2, rareResponses.get(0).getFingerprint());
    }

    @Test
    public void testGetRareResponsesWithMultipleRareResponses() {
        List<VectorResponse> responses = new ArrayList<>();
        TestVector vector1 = new TestVector("vector1");
        TestVector vector2 = new TestVector("vector2");
        TestVector vector3 = new TestVector("vector3");
        TestVector vector4 = new TestVector("vector4");

        ResponseFingerprint fingerprint1 =
                new ResponseFingerprint(new ArrayList<>(), new ArrayList<>(), SocketState.CLOSED);
        ResponseFingerprint fingerprint2 =
                new ResponseFingerprint(new ArrayList<>(), new ArrayList<>(), SocketState.TIMEOUT);
        ResponseFingerprint fingerprint3 =
                new ResponseFingerprint(
                        new ArrayList<>(), new ArrayList<>(), SocketState.DATA_AVAILABLE);

        // vector1 and vector2 have fingerprint1, vector3 has fingerprint2, vector4 has fingerprint3
        responses.add(new VectorResponse(vector1, fingerprint1));
        responses.add(new VectorResponse(vector2, fingerprint1));
        responses.add(new VectorResponse(vector3, fingerprint2));
        responses.add(new VectorResponse(vector4, fingerprint3));

        InformationLeakTest<SimpleTestInfo> test =
                new InformationLeakTest<>(new SimpleTestInfo(), responses);

        // Get responses that occurred at most twice
        List<VectorResponse> rareResponses = test.getRareResponses(2);
        assertEquals(4, rareResponses.size()); // All responses occur at most twice

        // Get responses that occurred at most once
        rareResponses = test.getRareResponses(1);
        assertEquals(2, rareResponses.size()); // vector3 and vector4

        // Verify the rare responses
        boolean foundVector3 = false;
        boolean foundVector4 = false;
        for (VectorResponse response : rareResponses) {
            if (response.getVector().equals(vector3)) {
                foundVector3 = true;
                assertEquals(fingerprint2, response.getFingerprint());
            } else if (response.getVector().equals(vector4)) {
                foundVector4 = true;
                assertEquals(fingerprint3, response.getFingerprint());
            }
        }
        assertTrue(foundVector3);
        assertTrue(foundVector4);
    }

    @Test
    public void testGetRareResponsesWithNoRareResponses() {
        List<VectorResponse> responses = new ArrayList<>();
        TestVector vector1 = new TestVector("vector1");
        TestVector vector2 = new TestVector("vector2");
        TestVector vector3 = new TestVector("vector3");

        ResponseFingerprint fingerprint1 =
                new ResponseFingerprint(new ArrayList<>(), new ArrayList<>(), SocketState.CLOSED);

        // All vectors have the same fingerprint
        responses.add(new VectorResponse(vector1, fingerprint1));
        responses.add(new VectorResponse(vector2, fingerprint1));
        responses.add(new VectorResponse(vector3, fingerprint1));

        InformationLeakTest<SimpleTestInfo> test =
                new InformationLeakTest<>(new SimpleTestInfo(), responses);

        // Get responses that occurred at most twice
        List<VectorResponse> rareResponses = test.getRareResponses(2);
        assertTrue(rareResponses.isEmpty()); // All responses occur 3 times

        // Get responses that occurred at most 3 times
        rareResponses = test.getRareResponses(3);
        assertEquals(3, rareResponses.size()); // All responses occur exactly 3 times
    }

    @Test
    public void testGetRareResponsesIntegrationWithExtendedTest() {
        List<VectorResponse> initialResponses = new ArrayList<>();
        TestVector vector1 = new TestVector("vector1");
        TestVector vector2 = new TestVector("vector2");

        ResponseFingerprint fingerprint1 =
                new ResponseFingerprint(new ArrayList<>(), new ArrayList<>(), SocketState.CLOSED);
        ResponseFingerprint fingerprint2 =
                new ResponseFingerprint(new ArrayList<>(), new ArrayList<>(), SocketState.TIMEOUT);

        initialResponses.add(new VectorResponse(vector1, fingerprint1));
        initialResponses.add(new VectorResponse(vector2, fingerprint2));

        InformationLeakTest<SimpleTestInfo> test =
                new InformationLeakTest<>(new SimpleTestInfo(), initialResponses);

        // Initially both responses are unique
        List<VectorResponse> rareResponses = test.getRareResponses(1);
        assertEquals(2, rareResponses.size());

        // Extend the test with more responses
        List<VectorResponse> additionalResponses = new ArrayList<>();
        additionalResponses.add(new VectorResponse(vector1, fingerprint1));
        additionalResponses.add(new VectorResponse(vector1, fingerprint1));

        test.extendTestWithVectorResponses(additionalResponses);

        // Now only vector2's response is rare (occurring once)
        rareResponses = test.getRareResponses(1);
        // Since vector1 now occurs 3 times (1 initial + 2 additional) with fingerprint1,
        // but getRareResponses returns one VectorResponse per vector that had that fingerprint,
        // we expect 1 response for vector2 (which still occurs once)
        assertEquals(1, rareResponses.size());
        assertEquals(vector2, rareResponses.get(0).getVector());
        assertEquals(fingerprint2, rareResponses.get(0).getFingerprint());
    }
}
