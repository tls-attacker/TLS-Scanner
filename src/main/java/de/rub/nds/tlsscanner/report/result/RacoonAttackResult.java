/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.racoonattack.RacoonAttackProbabilities;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

public class RacoonAttackResult extends ProbeResult {

    private boolean reusesDheKey;

    private BigInteger reusedDheModulus;

    private BigInteger staticDhModulus;

    private boolean supportsSha384;

    private boolean supportsSha256;

    private boolean supportsLegacyPrf;

    private boolean supportsSslv3;

    private List<RacoonAttackProbabilities> attackProbabilityList;

    public RacoonAttackResult(boolean reusesDheKey, Integer dheModulusSize, BigInteger reusedDheModulus, Integer staticDhModulusSize, BigInteger staticDhModulus, boolean supportsStaticDh, boolean supportsSha384, boolean supportsSha256, boolean supportsLegacyPrf, boolean supportsSslv3) {
        super(ProbeType.RACOON_ATTACK);
        this.reusesDheKey = reusesDheKey;
        this.reusedDheModulus = reusedDheModulus;
        this.staticDhModulus = staticDhModulus;
        this.supportsSha384 = supportsSha384;
        this.supportsSha256 = supportsSha256;
        this.supportsLegacyPrf = supportsLegacyPrf;
        this.supportsSslv3 = supportsSslv3;
    }

    @Override
    protected void mergeData(SiteReport report) {
        List<RacoonAttackProbabilities> probabilityList = new LinkedList<>();
        if (staticDhModulus != null) {
            probabilityList.addAll(computeRacoonAttackProbabilities(staticDhModulus));
        }
        if (reusedDheModulus != null) {
            probabilityList.addAll(computeRacoonAttackProbabilities(staticDhModulus));
        }

    }

    private List<RacoonAttackProbabilities> computeRacoonAttackProbabilities(BigInteger modulus) {
        List<RacoonAttackProbabilities> probabilityList = new LinkedList<>();

        if (supportsLegacyPrf) {
            probabilityList.add(computeLegacyPrfProbability(modulus));
        }
        if (supportsSha256) {
            probabilityList.add(computeSha256Probability(modulus));
        }
        if (supportsSha384) {
            probabilityList.add(computeSha384Probability(modulus));
        }
        if (supportsSslv3) {
            probabilityList.add(computeSslv3Md5OuterProbability(modulus));
            probabilityList.add(computeSslv3Sha1AInnerProbability(modulus));
            probabilityList.add(computeSslv3Sha1BBInnerProbability(modulus));
            probabilityList.add(computeSslv3Sha1CCCInnerProbability(modulus));
        }
        return 
    }

    private RacoonAttackProbabilities computeLegacyPrfProbability(BigInteger modulus) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private RacoonAttackProbabilities computeSha256Probability(BigInteger modulus) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private RacoonAttackProbabilities computeSha384Probability(BigInteger modulus) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private RacoonAttackProbabilities computeSslv3Md5OuterProbability(BigInteger modulus) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private RacoonAttackProbabilities computeSslv3Sha1AInnerProbability(BigInteger modulus) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private RacoonAttackProbabilities computeSslv3Sha1BBInnerProbability(BigInteger modulus) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private RacoonAttackProbabilities computeSslv3Sha1CCCInnerProbability(BigInteger modulus) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private int bitsToNextSmallerBlock(int blocksize, BigInteger modulus, int fixedLength, int minimalPaddingLength, int contentLengthFieldSize) {
        int minimalPaddingSize = ArrayConverter.bigIntegerToByteArray(modulus).length + fixedLength + minimalPaddingLength + contentLengthFieldSize;
    }

}
