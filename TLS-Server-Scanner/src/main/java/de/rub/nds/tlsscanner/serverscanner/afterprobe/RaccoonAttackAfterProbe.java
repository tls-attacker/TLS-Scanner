/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack.RaccoonAttackProbabilities;
import de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack.RaccoonAttackPskProbabilities;
import de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack.RaccoonAttackVulnerabilityPosition;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/** This class analyzes all previously seen DH public keys and moduli. */
public class RaccoonAttackAfterProbe extends AfterProbe<ServerReport> {

    private static final int MAX_CONSIDERED_PSK_LENGTH_BYTES = 128;

    private static final double MAX_CONSIDERED_NUMBER_OF_GUESSES_PER_EQUATION = 0x0100000000000000L;

    private Boolean supportsSha384;

    private Boolean supportsSha256;

    private Boolean supportsLegacyPrf;

    private Boolean supportsSSLv3;

    private List<RaccoonAttackProbabilities> attackProbabilityList;

    public RaccoonAttackAfterProbe() {
        attackProbabilityList = new LinkedList<>();
    }

    @Override
    public void analyze(ServerReport report) {
        supportsLegacyPrf =
                report.getResult(TlsAnalyzedProperty.SUPPORTS_LEGACY_PRF) == TestResults.TRUE;
        supportsSha256 =
                report.getResult(TlsAnalyzedProperty.SUPPORTS_SHA256_PRF) == TestResults.TRUE;
        supportsSha384 =
                report.getResult(TlsAnalyzedProperty.SUPPORTS_SHA384_PRF) == TestResults.TRUE;
        supportsSSLv3 = report.getResult(TlsAnalyzedProperty.SUPPORTS_SSL_3) == TestResults.TRUE;
        ExtractedValueContainer<?> publicKeyContainer =
                report.getExtractedValueContainerMap().get(TrackableValueType.DHE_PUBLICKEY);
        List<?> extractedValueList = publicKeyContainer.getExtractedValueList();
        Map<Integer, BigInteger> smallestByteSizeModuloMap =
                generateSmallestByteSizeModuloMap(extractedValueList);
        for (Integer i : smallestByteSizeModuloMap.keySet()) {
            BigInteger modulo = smallestByteSizeModuloMap.get(i);
            attackProbabilityList.addAll(computeRaccoonAttackProbabilities(modulo));
        }
        report.putResult(TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES, attackProbabilityList);

        TestResult reusesDhPublicKey = report.getResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY);
        if (reusesDhPublicKey == TestResults.TRUE) {
            report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK, TestResults.TRUE);
        } else {
            report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK, TestResults.FALSE);
        }
    }

    /**
     * Create a map which contains for each observed byte size the smallest seen modulus
     *
     * @param extractedValueList
     * @return
     */
    public Map<Integer, BigInteger> generateSmallestByteSizeModuloMap(List<?> extractedValueList) {
        Map<Integer, BigInteger> smallestByteSizeModuloMap = new HashMap<>();
        for (Object o : extractedValueList) {
            DhPublicKey publicKey = (DhPublicKey) o;
            byte[] modulo = ArrayConverter.bigIntegerToByteArray(publicKey.getModulus());
            if (smallestByteSizeModuloMap.containsKey(modulo.length)) {
                if (smallestByteSizeModuloMap.get(modulo.length).compareTo(publicKey.getModulus())
                        > 0) {
                    smallestByteSizeModuloMap.remove(modulo.length);
                    smallestByteSizeModuloMap.put(modulo.length, publicKey.getModulus());
                }
            } else {
                smallestByteSizeModuloMap.put(modulo.length, publicKey.getModulus());
            }
        }
        return smallestByteSizeModuloMap;
    }

    private List<RaccoonAttackProbabilities> computeRaccoonAttackProbabilities(BigInteger modulus) {
        List<RaccoonAttackProbabilities> probabilityList = new LinkedList<>();

        if (supportsLegacyPrf) {
            probabilityList.add(computeLegacyPrfProbability(modulus));
        }
        if (supportsSha256) {
            probabilityList.add(computeSha256PrfProbability(modulus));
        }
        if (supportsSha384) {
            probabilityList.add(computeSha384PrfProbability(modulus));
        }
        if (supportsSSLv3) {
            probabilityList.add(computeSSLv3OuterMd5Probability(modulus));
            probabilityList.add(computeSSLv3Sha1AInnerProbability(modulus));
            probabilityList.add(computeSSLv3Sha1BBInnerProbability(modulus));
            probabilityList.add(computeSSLv3Sha1CCCInnerProbability(modulus));
        }
        return probabilityList;
    }

    private RaccoonAttackProbabilities computeLegacyPrfProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 0;
        int maxPadding = blockLength - 8;
        int hashLengthField = 64;
        /** For Legacy PRF the input gets halved rounded up into the hash function */
        int inputLength = (ArrayConverter.bigIntegerToByteArray(modulus).length);
        if (inputLength % 2 == 1) {
            inputLength++;
        }
        inputLength = inputLength / 2;
        /** convert into bits */
        inputLength = inputLength * 8;

        int bitsToNextSmallerBlock =
                bitsToNextSmallerBlock(
                        blockLength, inputLength, fixedLength, maxPadding, hashLengthField);

        List<RaccoonAttackPskProbabilities> pskProbabilityList =
                computePskProbabilitiesList(
                        blockLength,
                        inputLength,
                        fixedLength,
                        maxPadding,
                        hashLengthField,
                        modulus);
        return new RaccoonAttackProbabilities(
                RaccoonAttackVulnerabilityPosition.TLS_LEGACY_PRF,
                bitsToNextSmallerBlock,
                attackSuccessChance(bitsToNextSmallerBlock, modulus),
                pskProbabilityList,
                modulus);
    }

    /** For PSK we have to attach 2 * 2 length bytes and the psk to the pms */
    private List<RaccoonAttackPskProbabilities> computePskProbabilitiesList(
            int blockLength,
            int inputLength,
            int fixedLength,
            int minPadding,
            int hashLengthField,
            BigInteger modulus) {
        List<RaccoonAttackPskProbabilities> pskProbabilityList = new LinkedList<>();
        for (int i = 0; i < MAX_CONSIDERED_PSK_LENGTH_BYTES; i++) {
            int bitsToNextSmallerBlockPsk =
                    bitsToNextSmallerBlock(
                            blockLength,
                            inputLength + 2 * 8 + 2 * 8 + i * 8,
                            fixedLength,
                            minPadding,
                            hashLengthField);
            BigDecimal attackSuccessChance =
                    attackSuccessChance(bitsToNextSmallerBlockPsk, modulus);
            if (attackSuccessChance
                            .multiply(
                                    new BigDecimal(
                                            "" + MAX_CONSIDERED_NUMBER_OF_GUESSES_PER_EQUATION,
                                            new MathContext(256, RoundingMode.DOWN)))
                            .compareTo(BigDecimal.ONE)
                    > 0) {
                pskProbabilityList.add(
                        new RaccoonAttackPskProbabilities(
                                i, bitsToNextSmallerBlockPsk, attackSuccessChance));
            } else {
                // TOO small probability
            }
            if (pskProbabilityList.size() >= 7) {
                return pskProbabilityList;
            }
        }
        return pskProbabilityList;
    }

    private BigDecimal attackSuccessChance(int bitsToNextSmallerBlock, BigInteger modulus) {
        BigInteger denominator = modulus.shiftRight(modulus.bitLength() - bitsToNextSmallerBlock);
        BigDecimal decFraction = BigDecimal.ONE;
        BigDecimal decDenominator = new BigDecimal(denominator);
        if (decDenominator.equals(BigDecimal.ZERO)) {
            return BigDecimal.ZERO;
        }
        return decFraction.divide(decDenominator, 128, RoundingMode.DOWN);
    }

    private RaccoonAttackProbabilities computeSha256PrfProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 0;
        int maxPadding = blockLength - 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock =
                bitsToNextSmallerBlock(
                        blockLength, inputLength, fixedLength, maxPadding, hashLengthField);

        List<RaccoonAttackPskProbabilities> pskProbabilityList =
                computePskProbabilitiesList(
                        blockLength,
                        inputLength,
                        fixedLength,
                        maxPadding,
                        hashLengthField,
                        modulus);
        return new RaccoonAttackProbabilities(
                RaccoonAttackVulnerabilityPosition.TLS12_SHA256PRF,
                bitsToNextSmallerBlock,
                attackSuccessChance(bitsToNextSmallerBlock, modulus),
                pskProbabilityList,
                modulus);
    }

    private RaccoonAttackProbabilities computeSha384PrfProbability(BigInteger modulus) {
        int blockLength = 1024;
        int fixedLength = 0;
        int maxPadding = blockLength - 8;
        int hashLengthField = 128;
        int inputLength = modulus.bitLength();
        int bitsToNextBorder =
                bitsToNextSmallerBlock(
                        blockLength, inputLength, fixedLength, maxPadding, hashLengthField);
        List<RaccoonAttackPskProbabilities> pskProbabilityList =
                computePskProbabilitiesList(
                        blockLength,
                        inputLength,
                        fixedLength,
                        maxPadding,
                        hashLengthField,
                        modulus);
        return new RaccoonAttackProbabilities(
                RaccoonAttackVulnerabilityPosition.TLS12_SHA384PRF,
                bitsToNextBorder,
                attackSuccessChance(bitsToNextBorder, modulus),
                pskProbabilityList,
                modulus);
    }

    private RaccoonAttackProbabilities computeSSLv3OuterMd5Probability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 160;
        int maxPadding = blockLength - 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock =
                bitsToNextSmallerBlock(
                        blockLength, inputLength, fixedLength, maxPadding, hashLengthField);

        List<RaccoonAttackPskProbabilities> pskProbabilityList =
                computePskProbabilitiesList(
                        blockLength,
                        inputLength,
                        fixedLength,
                        maxPadding,
                        hashLengthField,
                        modulus);
        return new RaccoonAttackProbabilities(
                RaccoonAttackVulnerabilityPosition.SSL3_OUTER_MD5,
                bitsToNextSmallerBlock,
                attackSuccessChance(bitsToNextSmallerBlock, modulus),
                pskProbabilityList,
                modulus);
    }

    private RaccoonAttackProbabilities computeSSLv3Sha1AInnerProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 65;
        int maxPadding = blockLength - 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock =
                bitsToNextSmallerBlock(
                        blockLength, inputLength, fixedLength, maxPadding, hashLengthField);

        List<RaccoonAttackPskProbabilities> pskProbabilityList =
                computePskProbabilitiesList(
                        blockLength,
                        inputLength,
                        fixedLength,
                        maxPadding,
                        hashLengthField,
                        modulus);
        return new RaccoonAttackProbabilities(
                RaccoonAttackVulnerabilityPosition.SSL3_INNER_SHA1_A,
                bitsToNextSmallerBlock,
                attackSuccessChance(bitsToNextSmallerBlock, modulus),
                pskProbabilityList,
                modulus);
    }

    private RaccoonAttackProbabilities computeSSLv3Sha1BBInnerProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 66;
        int maxPadding = blockLength - 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock =
                bitsToNextSmallerBlock(
                        blockLength, inputLength, fixedLength, maxPadding, hashLengthField);

        List<RaccoonAttackPskProbabilities> pskProbabilityList =
                computePskProbabilitiesList(
                        blockLength,
                        inputLength,
                        fixedLength,
                        maxPadding,
                        hashLengthField,
                        modulus);
        return new RaccoonAttackProbabilities(
                RaccoonAttackVulnerabilityPosition.SSL3_INNER_SHA1_BB,
                bitsToNextSmallerBlock,
                attackSuccessChance(bitsToNextSmallerBlock, modulus),
                pskProbabilityList,
                modulus);
    }

    private RaccoonAttackProbabilities computeSSLv3Sha1CCCInnerProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 67;
        int maxPadding = blockLength - 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock =
                bitsToNextSmallerBlock(
                        blockLength, inputLength, fixedLength, maxPadding, hashLengthField);

        List<RaccoonAttackPskProbabilities> pskProbabilityList =
                computePskProbabilitiesList(
                        blockLength,
                        inputLength,
                        fixedLength,
                        maxPadding,
                        hashLengthField,
                        modulus);
        return new RaccoonAttackProbabilities(
                RaccoonAttackVulnerabilityPosition.SSL3_INNER_SHA1_CCC,
                bitsToNextSmallerBlock,
                attackSuccessChance(bitsToNextSmallerBlock, modulus),
                pskProbabilityList,
                modulus);
    }

    private int bitsToNextSmallerBlock(
            int blocksize,
            int inputBitLength,
            int fixedLength,
            int minimalPaddingLength,
            int contentLengthFieldSize) {
        int minimalPaddingSize =
                inputBitLength + fixedLength + minimalPaddingLength + contentLengthFieldSize;
        return minimalPaddingSize % blocksize;
    }
}
