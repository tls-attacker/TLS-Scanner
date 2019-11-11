/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public class ECPointFormatResult extends ProbeResult {

    private TestResult supportsUncompressedPoint = TestResult.FALSE;
    private TestResult supportsANSIX962CompressedPrime = TestResult.FALSE;
    private TestResult supportsANSIX962CompressedChar2 = TestResult.FALSE;
    
    private final List<ECPointFormat> supportedFormats;
    
    public ECPointFormatResult(List<ECPointFormat> formats) {
        super(ProbeType.EC_POINT_FORMAT);
        this.supportedFormats = formats;
    }
    
    @Override
    protected void mergeData(SiteReport report) {
        if(supportedFormats != null)
        {
            for(ECPointFormat format: supportedFormats)
            {
                switch(format)
                {
                    case UNCOMPRESSED:
                        supportsUncompressedPoint = TestResult.TRUE;
                        break;
                    case ANSIX962_COMPRESSED_PRIME:
                        supportsANSIX962CompressedPrime = TestResult.TRUE;
                        break;
                    case ANSIX962_COMPRESSED_CHAR2:
                        supportsANSIX962CompressedChar2 = TestResult.TRUE;
                }   
            }
        }
        else
        {
            supportsUncompressedPoint = TestResult.COULD_NOT_TEST;
            supportsANSIX962CompressedPrime = TestResult.COULD_NOT_TEST;
            supportsANSIX962CompressedChar2 = TestResult.COULD_NOT_TEST;
        }
        report.putResult(AnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, supportsUncompressedPoint);
        report.putResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, supportsANSIX962CompressedPrime);
        report.putResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, supportsANSIX962CompressedChar2);
        
    }
    
}
