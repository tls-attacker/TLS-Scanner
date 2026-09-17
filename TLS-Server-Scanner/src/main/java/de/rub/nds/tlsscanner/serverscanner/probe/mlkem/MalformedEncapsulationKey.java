/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.mlkem;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.protocol.constants.MlKemParameters;
import de.rub.nds.protocol.crypto.kem.MlKemCalculator;
import de.rub.nds.protocol.crypto.kem.MlKemCodec;
import de.rub.nds.protocol.crypto.kem.MlKemPke;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.List;
import java.util.stream.IntStream;

/**
 * An ML-KEM encapsulation key that violates the modulus check of the encapsulation key check
 * defined in Section 7.2 of FIPS 203.
 *
 * <p>The modulus check requires that ek equals ByteEncode_12(ByteDecode_12(ek)). Since
 * ByteDecode_12 reduces every coefficient modulo q, this holds if and only if each of the 256 * k
 * coefficients encoded in the first 384 * k bytes of the key is smaller than q = 3329.
 */
public class MalformedEncapsulationKey {

    /** The largest value that fits into the 12 bits an uncompressed coefficient is encoded in. */
    public static final int MAXIMUM_COEFFICIENT = (1 << MlKemCodec.UNCOMPRESSED_BITS) - 1;

    /** Identifies how a key violates the modulus check, so that findings can be told apart. */
    public enum Type {
        // First coefficient is set to max value
        FIRST_COEFFICIENT_MAXIMUM,
        // First coefficient is exactly q, the first value in range to be rejected
        FIRST_COEFFICIENT_MODULUS,
        // Last corefficient set to max value to detect off by one
        LAST_COEFFICIENT_MAXIMUM,
        // Set all coefficients to max value to obtain the easiest to detect malformed public key
        ALL_COEFFICIENTS_MAXIMUM
    }

    private final NamedGroup namedGroup;
    private final MlKemParameters parameters;
    private final Type type;
    private final byte[] encapsulationKey;
    private final int[] offendingCoefficientIndices;
    private final int offendingCoefficientValue;

    private MalformedEncapsulationKey(
            NamedGroup namedGroup,
            Type type,
            byte[] encapsulationKey,
            int[] offendingCoefficientIndices,
            int offendingCoefficientValue) {
        this.namedGroup = namedGroup;
        this.parameters =
                (MlKemParameters) namedGroup.getAnyInvolvedPqGroup().getAsymmetricParameters();
        this.type = type;
        this.encapsulationKey = encapsulationKey;
        this.offendingCoefficientIndices = offendingCoefficientIndices;
        this.offendingCoefficientValue = offendingCoefficientValue;
    }

    /**
     * Provides an encapsulation key whose first coefficient is the largest value that can be
     * encoded in 12 bits. This is the most blatant violation of the modulus check and any server
     * performing it at all must reject the key.
     *
     * @param group The ML-KEM group, either a pure or a hybrid one
     * @return MalformedEncapsulationKey
     */
    public static MalformedEncapsulationKey firstCoefficientMaximum(NamedGroup group) {
        return singleCoefficient(group, Type.FIRST_COEFFICIENT_MAXIMUM, 0, MAXIMUM_COEFFICIENT);
    }

    /**
     * Provides an encapsulation key whose first coefficient is exactly q. This is the smallest
     * offending value there is and hence the only key that reveals an off by one in the comparison
     * a server performs.
     *
     * @param group The ML-KEM group, either a pure or a hybrid one
     * @return MalformedEncapsulationKey
     */
    public static MalformedEncapsulationKey firstCoefficientModulus(NamedGroup group) {
        return singleCoefficient(group, Type.FIRST_COEFFICIENT_MODULUS, 0, MlKemParameters.MODULUS);
    }

    /**
     * Provides an encapsulation key whose last coefficient is the largest value that can be encoded
     * in 12 bits. A server that only checks the first polynomial of the vector or that leaves the
     * final coefficient out of its loop accepts this key while rejecting the one returned by {@link
     * #firstCoefficientMaximum(NamedGroup)}.
     *
     * @param group The ML-KEM group, either a pure or a hybrid one
     * @return MalformedEncapsulationKey
     */
    public static MalformedEncapsulationKey lastCoefficientMaximum(NamedGroup group) {
        MlKemParameters parameters = getParameters(group);
        return singleCoefficient(
                group,
                Type.LAST_COEFFICIENT_MAXIMUM,
                getCoefficientCount(parameters) - 1,
                MAXIMUM_COEFFICIENT);
    }

    /**
     * Provides an encapsulation key in which every coefficient is the largest value that can be
     * encoded in 12 bits, that is a key whose encoded vector consists of 0xFF bytes only. The seed
     * rho is kept intact so that the key remains well formed everywhere the modulus check does not
     * apply.
     *
     * @param group The ML-KEM group, either a pure or a hybrid one
     * @return MalformedEncapsulationKey
     */
    public static MalformedEncapsulationKey allCoefficientsMaximum(NamedGroup group) {
        MlKemParameters parameters = getParameters(group);
        byte[] encapsulationKey = generateEncapsulationKey(parameters);
        int coefficientCount = getCoefficientCount(parameters);
        for (int index = 0; index < coefficientCount; index++) {
            setCoefficient(encapsulationKey, index, MAXIMUM_COEFFICIENT);
        }
        return new MalformedEncapsulationKey(
                group,
                Type.ALL_COEFFICIENTS_MAXIMUM,
                encapsulationKey,
                IntStream.range(0, coefficientCount).toArray(),
                MAXIMUM_COEFFICIENT);
    }

    /**
     * Provides all malformed encapsulation keys known for the given group, ordered from the most to
     * the least blatant violation of the modulus check.
     *
     * @param group The ML-KEM group, either a pure or a hybrid one
     * @return All malformed encapsulation keys for the group
     */
    public static List<MalformedEncapsulationKey> getAll(NamedGroup group) {
        return List.of(
                firstCoefficientMaximum(group),
                allCoefficientsMaximum(group),
                lastCoefficientMaximum(group),
                firstCoefficientModulus(group));
    }

    /**
     * Provides an encapsulation key that passes the encapsulation key check. Sending it is the
     * control for the malformed keys, as a server that rejects it either does not support the group
     * or aborted for a reason unrelated to the check.
     *
     * @param group The ML-KEM group, either a pure or a hybrid one
     * @return The encoded encapsulation key
     */
    public static byte[] getValidEncapsulationKey(NamedGroup group) {
        return generateEncapsulationKey(getParameters(group));
    }

    private static MalformedEncapsulationKey singleCoefficient(
            NamedGroup group, Type type, int coefficientIndex, int value) {
        MlKemParameters parameters = getParameters(group);
        byte[] encapsulationKey = generateEncapsulationKey(parameters);
        setCoefficient(encapsulationKey, coefficientIndex, value);
        return new MalformedEncapsulationKey(
                group, type, encapsulationKey, new int[] {coefficientIndex}, value);
    }

    private static byte[] generateEncapsulationKey(MlKemParameters parameters) {
        return MlKemCalculator.generateKeyPair(parameters, new BadRandom())
                .getLeft()
                .getEncapsulationKey();
    }

    /**
     * Overwrites a single coefficient of the encoded vector in place. The bits of a coefficient are
     * stored least significant bit first and two coefficients share a byte, exactly as {@link
     * MlKemCodec#byteEncode} packs them.
     *
     * @param encapsulationKey The encoded encapsulation key to modify
     * @param coefficientIndex The index of the coefficient within the whole vector
     * @param value The value to write, which may exceed q
     */
    private static void setCoefficient(byte[] encapsulationKey, int coefficientIndex, int value) {
        int bitPosition = coefficientIndex * MlKemCodec.UNCOMPRESSED_BITS;
        for (int bit = 0; bit < MlKemCodec.UNCOMPRESSED_BITS; bit++) {
            int position = bitPosition + bit;
            int mask = 1 << (position & 7);
            if (((value >> bit) & 1) == 1) {
                encapsulationKey[position >> 3] |= (byte) mask;
            } else {
                encapsulationKey[position >> 3] &= (byte) ~mask;
            }
        }
    }

    /** Returns the number of coefficients encoded in an encapsulation key, that is 256 * k. */
    private static int getCoefficientCount(MlKemParameters parameters) {
        return parameters.getK() * MlKemParameters.POLYNOMIAL_DEGREE;
    }

    private static MlKemParameters getParameters(NamedGroup group) {
        if (!group.isMlKemGroup()) {
            throw new UnsupportedOperationException(
                    "Unable to yield an encapsulation key for unsupported group type "
                            + group.name());
        }
        return (MlKemParameters) group.getAnyInvolvedPqGroup().getAsymmetricParameters();
    }

    public NamedGroup getNamedGroup() {
        return namedGroup;
    }

    public MlKemParameters getParameters() {
        return parameters;
    }

    public Type getType() {
        return type;
    }

    /**
     * Returns the encoded encapsulation key. For hybrid groups this is only the ML-KEM part of the
     * key share, the classic part is left to the caller.
     *
     * @return The encapsulation key bytes
     */
    public byte[] getEncapsulationKey() {
        return encapsulationKey.clone();
    }

    /**
     * Returns the number of bytes the encoded vector occupies, that is the part of the key the
     * modulus check covers. The remaining bytes hold the seed rho.
     *
     * @return The length of the encoded vector in bytes
     */
    public int getEncodedVectorSizeBytes() {
        return parameters.getEncapsulationKeySizeBytes() - MlKemPke.MATRIX_SEED_SIZE_BYTES;
    }

    /** Returns the indices of the coefficients that were raised above q. */
    public int[] getOffendingCoefficientIndices() {
        return offendingCoefficientIndices.clone();
    }

    /** Returns the value the offending coefficients were set to. */
    public int getOffendingCoefficientValue() {
        return offendingCoefficientValue;
    }
}
