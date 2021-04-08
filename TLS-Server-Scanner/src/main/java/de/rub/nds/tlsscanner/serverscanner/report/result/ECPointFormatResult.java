/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.List;

public class ECPointFormatResult extends ProbeResult {

    private TestResult supportsUncompressedPoint = TestResult.FALSE;
    private TestResult supportsANSIX962CompressedPrime = TestResult.FALSE;
    private TestResult supportsANSIX962CompressedChar2 = TestResult.FALSE;

    private final List<ECPointFormat> supportedFormats;
    private final TestResult tls13SecpCompression;

    public ECPointFormatResult(List<ECPointFormat> formats, TestResult tls13SecpCompression) {
        super(ProbeType.EC_POINT_FORMAT);
        this.supportedFormats = formats;
        this.tls13SecpCompression = tls13SecpCompression;
    }

    @Override
    protected void mergeData(SiteReport report) {
        if (supportedFormats != null) {
            for (ECPointFormat format : supportedFormats) {
                switch (format) {
                    case UNCOMPRESSED:
                        supportsUncompressedPoint = TestResult.TRUE;
                        break;
                    case ANSIX962_COMPRESSED_PRIME:
                        supportsANSIX962CompressedPrime = TestResult.TRUE;
                        break;
                    case ANSIX962_COMPRESSED_CHAR2:
                        supportsANSIX962CompressedChar2 = TestResult.TRUE;
                        break;
                    default: // will never occur as all enum types are caught
                        ;
                }
            }
        } else {
            supportsUncompressedPoint = TestResult.COULD_NOT_TEST;
            supportsANSIX962CompressedPrime = TestResult.COULD_NOT_TEST;
            supportsANSIX962CompressedChar2 = TestResult.COULD_NOT_TEST;
        }
        report.putResult(AnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, supportsUncompressedPoint);
        report.putResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, supportsANSIX962CompressedPrime);
        report.putResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, supportsANSIX962CompressedChar2);
        if (tls13SecpCompression != null) {
            report.putResult(AnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION, tls13SecpCompression);
        } else {
            report.putResult(AnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION, TestResult.COULD_NOT_TEST);
        }
    }

}
