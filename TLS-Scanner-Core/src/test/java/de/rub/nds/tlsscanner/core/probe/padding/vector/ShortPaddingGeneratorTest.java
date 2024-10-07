/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding.vector;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ShortPaddingGeneratorTest {

    private ShortPaddingGenerator generator;

    @BeforeEach
    public void setUp() {
        generator = new ShortPaddingGenerator();
    }

    @Test
    public void testGetVectors() {
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isCBC()) {
                List<PaddingVector> vectors = generator.getVectors(suite, ProtocolVersion.TLS12);
                for (PaddingVector vector : vectors) {
                    int length = vector.getRecordLength(suite, ProtocolVersion.TLS12, 4);
                    assertEquals(
                            ShortPaddingGenerator.DEFAULT_CIPHERTEXT_LENGTH,
                            length,
                            "We only create vectors of the same length to omit false positives");
                }
            }
        }
    }

    /** Test of createBasicMacVectors method, of class ShortPaddingGenerator. */
    @Test
    public void testCreateBasicMacVectors() {
        List<PaddingVector> vectors =
                generator.createBasicMacVectors(
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12);
        assertEquals(3, vectors.size());
        int macSize =
                AlgorithmResolver.getMacAlgorithm(
                                ProtocolVersion.TLS12,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
                        .getMacLength();
        VariableModification modification = ((TripleVector) vectors.get(0)).getCleanModification();
        ModifiableByteArray array = new ModifiableByteArray();
        array.setModification(modification);
        byte[] expectedPlain =
                new byte
                        [ShortPaddingGenerator.DEFAULT_CIPHERTEXT_LENGTH
                                - ShortPaddingGenerator.DEFAULT_PADDING_LENGTH
                                - macSize];
        assertArrayEquals(expectedPlain, array.getValue());
    }

    /** Test of createMissingMacByteVectors method, of class ShortPaddingGenerator. */
    @Test
    public void testCreateMissingMacByteVectors() {
        List<PaddingVector> vectors =
                generator.createMissingMacByteVectors(
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12);
        assertEquals(2, vectors.size());
        int macSize =
                AlgorithmResolver.getMacAlgorithm(
                                ProtocolVersion.TLS12,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
                        .getMacLength();
        VariableModification modification = ((TripleVector) vectors.get(0)).getCleanModification();
        ModifiableByteArray array = new ModifiableByteArray();
        array.setModification(modification);
        assertArrayEquals(new byte[0], array.getValue(), "Validation of clean bytes");

        modification = ((TripleVector) vectors.get(0)).getPaddingModification();
        array = new ModifiableByteArray();
        array.setModification(modification);
        byte[] expectedPadding =
                generator.createPaddingBytes(
                        ShortPaddingGenerator.DEFAULT_CIPHERTEXT_LENGTH - macSize);
        assertArrayEquals(expectedPadding, array.getValue(), "Validation of used padding");

        byte[] macToModify = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
        modification = ((TripleVector) vectors.get(0)).getMacModification();
        array = new ModifiableByteArray();
        array.setOriginalValue(macToModify);
        array.setModification(modification);
        byte[] expectedMac = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
        assertArrayEquals(
                expectedMac, array.getValue(), "Validation of the deleted first byte in MAC");

        modification = ((TripleVector) vectors.get(1)).getMacModification();
        array = new ModifiableByteArray();
        array.setOriginalValue(macToModify);
        array.setModification(modification);
        expectedMac = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
        assertArrayEquals(
                expectedMac, array.getValue(), "Validation of the deleted last byte in MAC");
    }

    /** Test of createOnlyPaddingVectors method, of class ShortPaddingGenerator. */
    @Test
    public void testCreateOnlyPaddingVectors() {
        List<PaddingVector> vectors =
                generator.createOnlyPaddingVectors(
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12);
        assertEquals(2, vectors.size());

        Record r = vectors.get(0).createRecord();
        r.getComputations().setPlainRecordBytes(new byte[20]);
        byte[] expectedPadding =
                new byte[] {
                    79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79,
                    79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79,
                    79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79,
                    79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79
                };
        assertArrayEquals(
                expectedPadding,
                r.getComputations().getPlainRecordBytes().getValue(),
                "Validation of the first explicit padding");

        r = vectors.get(1).createRecord();
        r.getComputations().setPlainRecordBytes(new byte[20]);
        expectedPadding =
                new byte[] {
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                };
        assertArrayEquals(
                expectedPadding,
                r.getComputations().getPlainRecordBytes().getValue(),
                "Validation of the second explicit padding");
    }

    /** Test of createClassicModifiedPadding method, of class ShortPaddingGenerator. */
    @Test
    public void testCreateClassicModifiedPadding() {
        List<PaddingVector> vectors =
                generator.createClassicModifiedPadding(
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12);
        assertEquals(18, vectors.size());

        byte[] plainRecordBytes = getPlainRecordBytesFromVector(vectors.get(0));
        byte[] expected =
                new byte[] {
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    (byte) 0xBB,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B
                };
        assertArrayEquals(expected, plainRecordBytes, "Validation of the first invalid padding");

        plainRecordBytes = getPlainRecordBytesFromVector(vectors.get(1));
        expected =
                new byte[] {
                    00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x33, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B
                };
        assertArrayEquals(expected, plainRecordBytes, "Validation of the second invalid padding");

        plainRecordBytes = getPlainRecordBytesFromVector(vectors.get(2));
        expected =
                new byte[] {
                    00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3A
                };
        assertArrayEquals(expected, plainRecordBytes, "Validation of the second invalid padding");

        plainRecordBytes = getPlainRecordBytesFromVector(vectors.get(3));
        expected =
                new byte[] {
                    01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B
                };
        assertArrayEquals(expected, plainRecordBytes, "Validation of the second invalid padding");

        // TODO Add intermediate tests
        plainRecordBytes = getPlainRecordBytesFromVector(vectors.get(6));
        expected =
                new byte[] {
                    01,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    00,
                    (byte) 0xBB,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B,
                    0x3B
                };
        assertArrayEquals(expected, plainRecordBytes, "Validation of the second invalid padding");

        plainRecordBytes = getPlainRecordBytesFromVector(vectors.get(7));
        expected =
                new byte[] {
                    01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x33, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                };
        assertArrayEquals(expected, plainRecordBytes, "Validation of the second invalid padding");

        plainRecordBytes = getPlainRecordBytesFromVector(vectors.get(8));
        expected =
                new byte[] {
                    01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B,
                    0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3B, 0x3A
                };
        assertArrayEquals(expected, plainRecordBytes, "Validation of the second invalid padding");
    }

    private byte[] getPlainRecordBytesFromVector(PaddingVector vector) {
        Record r = vector.createRecord();
        r.setCleanProtocolMessageBytes(new byte[20]);
        r.getComputations().setMac(new byte[20]);
        r.getComputations().setPadding(new byte[20]);
        return ArrayConverter.concatenate(
                r.getCleanProtocolMessageBytes().getValue(),
                r.getComputations().getMac().getValue(),
                r.getComputations().getPadding().getValue());
    }

    /** Test of createFlippedModifications method, of class ShortPaddingGenerator. */
    @Test
    public void testCreateFlippedModifications() {
        List<ByteArrayXorModification> modifications = generator.createFlippedModifications(10);
        ModifiableByteArray array = new ModifiableByteArray();
        array.setOriginalValue(new byte[10]);
        byte[] expected = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        array.setModification(modifications.get(0));
        assertArrayEquals(expected, array.getValue(), "Last byte should be xored with 0x01");
        expected = new byte[] {0, 0, 0, 0, 0, 8, 0, 0, 0, 0};
        array.setModification(modifications.get(1));
        assertArrayEquals(expected, array.getValue(), "Middle byte should be xored with 0x08");
        expected = new byte[] {(byte) 128, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        array.setModification(modifications.get(2));
        assertArrayEquals(expected, array.getValue(), "First byte should be xored with 0x80");
    }
}
