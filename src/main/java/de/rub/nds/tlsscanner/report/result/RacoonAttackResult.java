/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.racoonattack.RacoonAttackProbabilities;
import de.rub.nds.tlsscanner.report.result.racoonattack.RacoonAttackPskProbabilities;
import de.rub.nds.tlsscanner.report.result.racoonattack.RacoonAttackVulnerabilityPosition;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.LinkedList;
import java.util.List;

public class RacoonAttackResult extends ProbeResult {

    private static final int MAX_CONSIDERED_PSK_LENGTH_BYTES = 64;

    private static final double MAX_CONSIDERED_NUMBER_OF_GUESSES_PER_EQUATION = 1 << 40;

    private BigInteger reusedDheModulus;

    private BigInteger staticDhModulus;

    private Boolean supportsSha384;

    private Boolean supportsSha256Sha1;

    private Boolean supportsLegacyPrf;

    private Boolean supportsSslv3;

    private List<RacoonAttackProbabilities> attackProbabilityList;

    private boolean didNotExecute = false;

    public RacoonAttackResult() {
        super(ProbeType.RACOON_ATTACK);
        didNotExecute = true;
    }

    public RacoonAttackResult(BigInteger reusedDheModulus, BigInteger staticDhModulus, boolean supportsSha384, boolean supportsSha256, boolean supportsLegacyPrf, boolean supportsSslv3) {
        super(ProbeType.RACOON_ATTACK);
        this.reusedDheModulus = reusedDheModulus;
        this.staticDhModulus = staticDhModulus;
        this.supportsSha384 = supportsSha384;
        this.supportsSha256Sha1 = supportsSha256;
        this.supportsLegacyPrf = supportsLegacyPrf;
        this.supportsSslv3 = supportsSslv3;
        System.out.println("RC: " + this.toString());
    }

    @Override
    public String toString() {
        return "RacoonAttackResult{" + "reusedDheModulus=" + reusedDheModulus + ", staticDhModulus=" + staticDhModulus + ", supportsSha384=" + supportsSha384 + ", supportsSha256Sha1=" + supportsSha256Sha1 + ", supportsLegacyPrf=" + supportsLegacyPrf + ", supportsSslv3=" + supportsSslv3 + ", attackProbabilityList=" + attackProbabilityList + ", didNotExecute=" + didNotExecute + '}';
    }

    @Override
    protected void mergeData(SiteReport report) {

        if (didNotExecute) {
            report.putResult(AnalyzedProperty.VULNERABLE_TO_RACOON_ATTACK, TestResult.COULD_NOT_TEST);
            return;
        }
        attackProbabilityList = new LinkedList<>();
        if (staticDhModulus != null) {
            attackProbabilityList.addAll(computeRacoonAttackProbabilities(staticDhModulus));
        }
        if (reusedDheModulus != null) {
            attackProbabilityList.addAll(computeRacoonAttackProbabilities(reusedDheModulus));
        }
        report.setRacoonAttackProbabilities(attackProbabilityList);
        Boolean vulnerable = false;
        for (RacoonAttackProbabilities probability : attackProbabilityList) {
            if (probability.getChanceForEquation().multiply(new BigDecimal(MAX_CONSIDERED_NUMBER_OF_GUESSES_PER_EQUATION)).intValue() > 0) {
                vulnerable = true;
                break;
            }
        }
        report.putResult(AnalyzedProperty.VULNERABLE_TO_RACOON_ATTACK, vulnerable);
    }

    private List<RacoonAttackProbabilities> computeRacoonAttackProbabilities(BigInteger modulus) {
        List<RacoonAttackProbabilities> probabilityList = new LinkedList<>();

        if (supportsLegacyPrf) {
            probabilityList.add(computeLegacyPrfProbability(modulus));
        }
        if (supportsSha256Sha1) {
            probabilityList.add(computeSha256PrfProbability(modulus));
        }
        if (supportsSha384) {
            probabilityList.add(computeSha384PrfProbability(modulus));
        }
        if (supportsSslv3) {
            probabilityList.add(computeSslv3OuterMd5Probability(modulus));
            probabilityList.add(computeSslv3Sha1AInnerProbability(modulus));
            probabilityList.add(computeSslv3Sha1BBInnerProbability(modulus));
            probabilityList.add(computeSslv3Sha1CCCInnerProbability(modulus));
        }
        return probabilityList;
    }

    private RacoonAttackProbabilities computeLegacyPrfProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 0;
        int minPadding = 8;
        int hashLengthField = 64;
        /**
         * For Legacy PRF the input gets halved rounded up into the hash
         * function
         */
        int inputLength = (ArrayConverter.bigIntegerToByteArray(modulus).length);
        if (inputLength % 2 == 1) {
            inputLength++;
        }
        inputLength = inputLength / 2;
        /**
         * convert into bits
         */
        inputLength = inputLength * 8;

        int bitsToNextSmallerBlock = bitsToNextSmallerBlock(blockLength, inputLength, fixedLength, minPadding, hashLengthField);

        List<RacoonAttackPskProbabilities> pskProbabilityList = computePskProbabilitiesList(blockLength, inputLength, fixedLength, minPadding, hashLengthField, modulus);
        return new RacoonAttackProbabilities(RacoonAttackVulnerabilityPosition.TLS10_11_LEGACY, bitsToNextSmallerBlock, attackSuccessChance(bitsToNextSmallerBlock, modulus), pskProbabilityList);
    }

    /**
     * For PSK we have to attach 2 * 2 length byts and the psk to the pms
     */
    private List<RacoonAttackPskProbabilities> computePskProbabilitiesList(int blockLänge, int inputLength, int fixedLength, int minPadding, int hashLengthField, BigInteger modulus) {
        List<RacoonAttackPskProbabilities> pskProbabilityList = new LinkedList<>();
        for (int i = 0; i < MAX_CONSIDERED_PSK_LENGTH_BYTES; i++) {
            int bitsToNextSmallerBlockPsk = bitsToNextSmallerBlock(blockLänge, inputLength + 2 * 8 + 2 * 8 + i * 8, fixedLength, minPadding, hashLengthField);
            BigDecimal attackSuccessChance = attackSuccessChance(bitsToNextSmallerBlockPsk, modulus);
            pskProbabilityList.add(new RacoonAttackPskProbabilities(i, bitsToNextSmallerBlockPsk, attackSuccessChance));
        }
        return pskProbabilityList;
    }

    private BigDecimal attackSuccessChance(int bitsToNextSmallerBlock, BigInteger modulus) {
        BigInteger denominator = modulus.shiftRight(modulus.bitLength() - bitsToNextSmallerBlock);
        BigDecimal decFraction = BigDecimal.ONE;
        BigDecimal decDenominator = new BigDecimal(denominator);
        if(decDenominator.equals(BigDecimal.ZERO))
        {
            return BigDecimal.ZERO;
        }
        return decFraction.divide(decDenominator, 128, RoundingMode.DOWN);
    }

    private RacoonAttackProbabilities computeSha256PrfProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 0;
        int minPadding = 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock = bitsToNextSmallerBlock(blockLength, inputLength, fixedLength, minPadding, hashLengthField);

        List<RacoonAttackPskProbabilities> pskProbabilityList = computePskProbabilitiesList(blockLength, inputLength, fixedLength, minPadding, hashLengthField, modulus);
        return new RacoonAttackProbabilities(RacoonAttackVulnerabilityPosition.TLS12_SHA256SHA1, bitsToNextSmallerBlock, attackSuccessChance(bitsToNextSmallerBlock, modulus), pskProbabilityList);

    }

    private RacoonAttackProbabilities computeSha384PrfProbability(BigInteger modulus) {
        int blockLength = 1024;
        int fixedLength = 0;
        int minPadding = 8;
        int hashLengthField = 128;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock = bitsToNextSmallerBlock(blockLength, inputLength, fixedLength, minPadding, hashLengthField);

        List<RacoonAttackPskProbabilities> pskProbabilityList = computePskProbabilitiesList(blockLength, inputLength, fixedLength, minPadding, hashLengthField, modulus);
        return new RacoonAttackProbabilities(RacoonAttackVulnerabilityPosition.TLS12_SHA384, bitsToNextSmallerBlock, attackSuccessChance(bitsToNextSmallerBlock, modulus), pskProbabilityList);
    }

    private RacoonAttackProbabilities computeSslv3OuterMd5Probability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 160;
        int minPadding = 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock = bitsToNextSmallerBlock(blockLength, inputLength, fixedLength, minPadding, hashLengthField);

        List<RacoonAttackPskProbabilities> pskProbabilityList = computePskProbabilitiesList(blockLength, inputLength, fixedLength, minPadding, hashLengthField, modulus);
        return new RacoonAttackProbabilities(RacoonAttackVulnerabilityPosition.SSL3_OUTER_MD5, bitsToNextSmallerBlock, attackSuccessChance(bitsToNextSmallerBlock, modulus), pskProbabilityList);
    }

    private RacoonAttackProbabilities computeSslv3Sha1AInnerProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 65;
        int minPadding = 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock = bitsToNextSmallerBlock(blockLength, inputLength, fixedLength, minPadding, hashLengthField);

        List<RacoonAttackPskProbabilities> pskProbabilityList = computePskProbabilitiesList(blockLength, inputLength, fixedLength, minPadding, hashLengthField, modulus);
        return new RacoonAttackProbabilities(RacoonAttackVulnerabilityPosition.SSL3_INNER_SHA1_A, bitsToNextSmallerBlock, attackSuccessChance(bitsToNextSmallerBlock, modulus), pskProbabilityList);
    }

    private RacoonAttackProbabilities computeSslv3Sha1BBInnerProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 66;
        int minPadding = 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock = bitsToNextSmallerBlock(blockLength, inputLength, fixedLength, minPadding, hashLengthField);

        List<RacoonAttackPskProbabilities> pskProbabilityList = computePskProbabilitiesList(blockLength, inputLength, fixedLength, minPadding, hashLengthField, modulus);
        return new RacoonAttackProbabilities(RacoonAttackVulnerabilityPosition.SSL3_INNER_SHA1_BB, bitsToNextSmallerBlock, attackSuccessChance(bitsToNextSmallerBlock, modulus), pskProbabilityList);
    }

    private RacoonAttackProbabilities computeSslv3Sha1CCCInnerProbability(BigInteger modulus) {
        int blockLength = 512;
        int fixedLength = 67;
        int minPadding = 8;
        int hashLengthField = 64;
        int inputLength = modulus.bitLength();

        int bitsToNextSmallerBlock = bitsToNextSmallerBlock(blockLength, inputLength, fixedLength, minPadding, hashLengthField);

        List<RacoonAttackPskProbabilities> pskProbabilityList = computePskProbabilitiesList(blockLength, inputLength, fixedLength, minPadding, hashLengthField, modulus);
        return new RacoonAttackProbabilities(RacoonAttackVulnerabilityPosition.SSL3_INNER_SHA1_CCC, bitsToNextSmallerBlock, attackSuccessChance(bitsToNextSmallerBlock, modulus), pskProbabilityList);
    }

    private int bitsToNextSmallerBlock(int blocksize, int inputBitLength, int fixedLength, int minimalPaddingLength, int contentLengthFieldSize) {
        int minimalPaddingSize = inputBitLength + fixedLength + minimalPaddingLength + contentLengthFieldSize;
        return minimalPaddingSize % blocksize;
    }

}
