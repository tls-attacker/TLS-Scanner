/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.mlkem;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.constants.MlKemParameters;
import de.rub.nds.protocol.crypto.kem.MlKemCalculator;
import de.rub.nds.protocol.crypto.kem.MlKemCodec;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class MalformedEncapsulationKeyTest {

    private static Stream<NamedGroup> mlKemGroups() {
        return Arrays.stream(NamedGroup.values()).filter(NamedGroup::isMlKemGroup);
    }

    /** Reads a coefficient without reducing it modulo q, unlike MlKemCodec#byteDecode. */
    private static int getRawCoefficient(byte[] encapsulationKey, int coefficientIndex) {
        int bitPosition = coefficientIndex * MlKemCodec.UNCOMPRESSED_BITS;
        int coefficient = 0;
        for (int bit = 0; bit < MlKemCodec.UNCOMPRESSED_BITS; bit++) {
            int position = bitPosition + bit;
            coefficient |= ((encapsulationKey[position >> 3] >> (position & 7)) & 1) << bit;
        }
        return coefficient;
    }

    /** All three parameter sets must be reachable, through pure as well as hybrid groups. */
    @Test
    public void testAllParameterSetsAreCovered() {
        List<MlKemParameters> covered =
                mlKemGroups()
                        .map(group -> MalformedEncapsulationKey.firstCoefficientMaximum(group))
                        .map(MalformedEncapsulationKey::getParameters)
                        .distinct()
                        .toList();
        assertEquals(
                MlKemParameters.values().length,
                covered.size(),
                "Every ML-KEM parameter set should be covered by at least one group");
    }

    /** The control key must pass the encapsulation key check of FIPS 203 Section 7.2. */
    @ParameterizedTest
    @MethodSource("mlKemGroups")
    public void testValidEncapsulationKeyPassesCheck(NamedGroup group) {
        MlKemParameters parameters =
                (MlKemParameters) group.getAnyInvolvedPqGroup().getAsymmetricParameters();
        byte[] validKey = MalformedEncapsulationKey.getValidEncapsulationKey(group);
        assertEquals(parameters.getEncapsulationKeySizeBytes(), validKey.length);
        assertTrue(
                MlKemCalculator.isValidEncapsulationKey(parameters, validKey),
                "The control key must be a valid encapsulation key for " + group);
    }

    /** Every malformed key must fail the modulus check but keep the length of a valid key. */
    @ParameterizedTest
    @MethodSource("mlKemGroups")
    public void testMalformedKeysFailCheckWithoutChangingLength(NamedGroup group) {
        List<MalformedEncapsulationKey> malformedKeys = MalformedEncapsulationKey.getAll(group);
        assertEquals(
                MalformedEncapsulationKey.Type.values().length,
                malformedKeys.size(),
                "Every type should be provided for " + group);

        for (MalformedEncapsulationKey malformedKey : malformedKeys) {
            MlKemParameters parameters = malformedKey.getParameters();
            byte[] encapsulationKey = malformedKey.getEncapsulationKey();
            assertEquals(
                    parameters.getEncapsulationKeySizeBytes(),
                    encapsulationKey.length,
                    "The length check must not be what rejects " + malformedKey.getType());
            assertFalse(
                    MlKemCalculator.isValidEncapsulationKey(parameters, encapsulationKey),
                    malformedKey.getType() + " must fail the check for " + group);
        }
    }

    /**
     * Only the offending coefficients may differ from the control key, and the seed rho must be
     * left untouched, as FIPS 203 does not constrain it.
     */
    @ParameterizedTest
    @MethodSource("mlKemGroups")
    public void testOnlyOffendingCoefficientsAreModified(NamedGroup group) {
        byte[] validKey = MalformedEncapsulationKey.getValidEncapsulationKey(group);

        for (MalformedEncapsulationKey malformedKey : MalformedEncapsulationKey.getAll(group)) {
            byte[] encapsulationKey = malformedKey.getEncapsulationKey();
            int vectorSize = malformedKey.getEncodedVectorSizeBytes();
            assertArrayEquals(
                    Arrays.copyOfRange(validKey, vectorSize, validKey.length),
                    Arrays.copyOfRange(encapsulationKey, vectorSize, encapsulationKey.length),
                    "The seed rho must not be modified by " + malformedKey.getType());

            int[] offendingIndices = malformedKey.getOffendingCoefficientIndices();
            int coefficientCount =
                    malformedKey.getParameters().getK() * MlKemParameters.POLYNOMIAL_DEGREE;
            for (int index = 0; index < coefficientCount; index++) {
                final int currentIndex = index;
                int expected =
                        Arrays.stream(offendingIndices)
                                        .anyMatch(offending -> offending == currentIndex)
                                ? malformedKey.getOffendingCoefficientValue()
                                : getRawCoefficient(validKey, index);
                assertEquals(
                        expected,
                        getRawCoefficient(encapsulationKey, index),
                        "Unexpected coefficient at index "
                                + index
                                + " for "
                                + malformedKey.getType()
                                + " of "
                                + group);
            }
        }
    }

    /** Every offending coefficient must lie in the only range that fails the check, [q, 4095]. */
    @ParameterizedTest
    @MethodSource("mlKemGroups")
    public void testOffendingValuesExceedTheModulus(NamedGroup group) {
        for (MalformedEncapsulationKey malformedKey : MalformedEncapsulationKey.getAll(group)) {
            int offendingValue = malformedKey.getOffendingCoefficientValue();
            assertTrue(
                    offendingValue >= MlKemParameters.MODULUS
                            && offendingValue <= MalformedEncapsulationKey.MAXIMUM_COEFFICIENT,
                    malformedKey.getType() + " uses a value that is not offending");
        }
    }

    /** The key that detects an off by one must use exactly q, the smallest offending value. */
    @ParameterizedTest
    @MethodSource("mlKemGroups")
    public void testModulusKeyUsesSmallestOffendingValue(NamedGroup group) {
        MalformedEncapsulationKey malformedKey =
                MalformedEncapsulationKey.firstCoefficientModulus(group);
        assertEquals(MlKemParameters.MODULUS, malformedKey.getOffendingCoefficientValue());
        assertEquals(
                MlKemParameters.MODULUS, getRawCoefficient(malformedKey.getEncapsulationKey(), 0));
    }

    /**
     * The last coefficient must be the final one of the whole vector, not of the first polynomial.
     */
    @ParameterizedTest
    @MethodSource("mlKemGroups")
    public void testLastCoefficientIsTheFinalOneOfTheVector(NamedGroup group) {
        MalformedEncapsulationKey malformedKey =
                MalformedEncapsulationKey.lastCoefficientMaximum(group);
        int coefficientCount =
                malformedKey.getParameters().getK() * MlKemParameters.POLYNOMIAL_DEGREE;
        assertArrayEquals(
                new int[] {coefficientCount - 1}, malformedKey.getOffendingCoefficientIndices());
        // The final coefficient always ends the encoded vector, right before the seed rho
        assertEquals(
                (byte) 0xFF,
                malformedKey.getEncapsulationKey()[malformedKey.getEncodedVectorSizeBytes() - 1]);
    }

    /** The key covering every coefficient must turn the whole encoded vector into 0xFF bytes. */
    @ParameterizedTest
    @MethodSource("mlKemGroups")
    public void testAllCoefficientsKeyFillsTheVector(NamedGroup group) {
        MalformedEncapsulationKey malformedKey =
                MalformedEncapsulationKey.allCoefficientsMaximum(group);
        byte[] expectedVector = new byte[malformedKey.getEncodedVectorSizeBytes()];
        Arrays.fill(expectedVector, (byte) 0xFF);
        assertArrayEquals(
                expectedVector,
                Arrays.copyOfRange(
                        malformedKey.getEncapsulationKey(),
                        0,
                        malformedKey.getEncodedVectorSizeBytes()));
    }

    /** Findings must be reproducible, so the keys may not depend on fresh randomness. */
    @ParameterizedTest
    @MethodSource("mlKemGroups")
    public void testKeysAreDeterministic(NamedGroup group) {
        assertArrayEquals(
                MalformedEncapsulationKey.getValidEncapsulationKey(group),
                MalformedEncapsulationKey.getValidEncapsulationKey(group));
        List<MalformedEncapsulationKey> first = MalformedEncapsulationKey.getAll(group);
        List<MalformedEncapsulationKey> second = MalformedEncapsulationKey.getAll(group);
        for (int i = 0; i < first.size(); i++) {
            assertEquals(first.get(i).getType(), second.get(i).getType());
            assertArrayEquals(
                    first.get(i).getEncapsulationKey(), second.get(i).getEncapsulationKey());
        }
    }

    /** A hybrid group must yield the key of the ML-KEM group it involves. */
    @Test
    public void testHybridGroupsYieldTheirMlKemParameters() {
        assertEquals(
                MalformedEncapsulationKey.firstCoefficientMaximum(NamedGroup.MLKEM768)
                        .getParameters(),
                MalformedEncapsulationKey.firstCoefficientMaximum(NamedGroup.X25519_MLKEM768)
                        .getParameters());
        assertArrayEquals(
                MalformedEncapsulationKey.firstCoefficientMaximum(NamedGroup.MLKEM768)
                        .getEncapsulationKey(),
                MalformedEncapsulationKey.firstCoefficientMaximum(NamedGroup.SECP256R1_MLKEM768)
                        .getEncapsulationKey());
    }

    /** Groups that do not involve ML-KEM must be rejected rather than silently mishandled. */
    @Test
    public void testUnsupportedGroupThrows() {
        assertThrows(
                UnsupportedOperationException.class,
                () -> MalformedEncapsulationKey.firstCoefficientMaximum(NamedGroup.ECDH_X25519));
    }
}
