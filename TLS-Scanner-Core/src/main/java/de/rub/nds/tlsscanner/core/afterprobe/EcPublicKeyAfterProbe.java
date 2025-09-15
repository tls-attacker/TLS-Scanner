/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * AfterProbe implementation that analyzes whether a server reuses EC (Elliptic Curve) public keys
 * across multiple handshakes
 *
 * @param <ReportT> the type of TLS scan report this probe operates on
 */
public class EcPublicKeyAfterProbe<ReportT extends TlsScanReport> extends AfterProbe<ReportT> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Analyzes the extracted EC public keys to determine if the server reuses the same public key
     * across multiple handshakes. Sets the result to TRUE if key reuse is detected, FALSE if all
     * keys are different, COULD_NOT_TEST if insufficient data is available, or ERROR_DURING_TEST if
     * an exception occurs.
     *
     * @param report the TLS scan report containing extracted EC public key data
     */
    @Override
    public void analyze(ReportT report) {
        ExtractedValueContainer<?> valueContainer =
                report.getExtractedValueContainerMap().get(TrackableValueType.ECDHE_PUBKEY);

        TestResult reuse;
        try {
            if (valueContainer.getNumberOfExtractedValues() >= 2) {
                if (!valueContainer.areAllValuesDifferent()) {
                    reuse = TestResults.TRUE;
                } else {
                    reuse = TestResults.FALSE;
                }
            } else {
                reuse = TestResults.COULD_NOT_TEST;
            }
        } catch (Exception e) {
            reuse = TestResults.ERROR_DURING_TEST;
        }

        int shortestBitLength = Integer.MAX_VALUE;
        if (valueContainer != null && !valueContainer.getExtractedValueList().isEmpty()) {
            for (Object o : valueContainer.getExtractedValueList()) {
                int bitLength;
                if (o instanceof EcdhPublicKey) {
                    EcdhPublicKey publicKey = (EcdhPublicKey) o;
                    bitLength = publicKey.getParameters().getElementSizeBits();
                } else if (o instanceof Point) {
                    Point point = (Point) o;
                    bitLength = point.getFieldX().getModulus().bitLength();
                } else {
                    LOGGER.warn("Object of unknown type: " + o.getClass());
                    bitLength = Integer.MAX_VALUE;
                }
                if (shortestBitLength > bitLength) {
                    shortestBitLength = bitLength;
                }
            }
        }

        report.putResult(TlsAnalyzedProperty.REUSES_EC_PUBLICKEY, reuse);
        if (shortestBitLength != Integer.MAX_VALUE) {
            report.putResult(TlsAnalyzedProperty.WEAKEST_ECDH_STRENGTH, shortestBitLength);
        }
    }
}
