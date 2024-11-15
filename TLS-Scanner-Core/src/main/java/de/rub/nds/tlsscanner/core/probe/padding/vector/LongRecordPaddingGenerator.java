/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding.vector;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

public class LongRecordPaddingGenerator extends PaddingVectorGenerator {

    @Override
    public List<PaddingVector> getVectors(CipherSuite suite, ProtocolVersion version) {
        // Total plaintext size is not allowed to be bigger than 16384
        // MAC + Plaintext
        List<PaddingVector> vectorList = new LinkedList<>();
        int blockSize = AlgorithmResolver.getCipher(suite).getBlocksize();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getMacLength();
        vectorList.add(
                new TripleVector(
                        "ValidPlainData",
                        "ValidPlainData",
                        new ByteArrayExplicitValueModification(new byte[16384]),
                        new ByteArrayExplicitValueModification(
                                new byte
                                        [AlgorithmResolver.getMacAlgorithm(version, suite)
                                                .getMacLength()]),
                        new ByteArrayExplicitValueModification(
                                createPaddingBytes(
                                        calculateValidPaddingSize(blockSize, macSize)))));
        vectorList.add(
                new TripleVector(
                        "InvalidPlainData",
                        "InvalidPlainData",
                        new ByteArrayExplicitValueModification(new byte[16385]),
                        new ByteArrayExplicitValueModification(
                                new byte
                                        [AlgorithmResolver.getMacAlgorithm(version, suite)
                                                .getMacLength()]),
                        new ByteArrayExplicitValueModification(
                                createPaddingBytes(
                                        calculateInvalidPaddingSize(blockSize, macSize)))));
        return vectorList;
    }

    private int calculateValidPaddingSize(int blocksize, int macSize) {
        return blocksize - (macSize % blocksize);
    }

    private int calculateInvalidPaddingSize(int blocksize, int macSize) {
        return (blocksize - (macSize % blocksize)) - 1;
    }
}
