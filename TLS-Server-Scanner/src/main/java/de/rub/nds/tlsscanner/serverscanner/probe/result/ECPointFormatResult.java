/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.List;

public class ECPointFormatResult extends ProbeResult<ServerReport> {

    private TestResult supportsUncompressedPoint = TestResult.FALSE;
    private TestResult supportsANSIX962CompressedPrime = TestResult.FALSE;
    private TestResult supportsANSIX962CompressedChar2 = TestResult.FALSE;

    private final List<ECPointFormat> supportedFormats;
    private final TestResult tls13SecpCompression;

    public ECPointFormatResult(List<ECPointFormat> formats, TestResult tls13SecpCompression) {
        super(TlsProbeType.EC_POINT_FORMAT);
        this.supportedFormats = formats;
        this.tls13SecpCompression = tls13SecpCompression;
    }

    @Override
    protected void mergeData(ServerReport report) {
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
        report.putResult(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, supportsUncompressedPoint);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, supportsANSIX962CompressedPrime);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, supportsANSIX962CompressedChar2);
        if (tls13SecpCompression != null) {
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION, tls13SecpCompression);
        } else {
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION, TestResult.COULD_NOT_TEST);
        }
    }

}
