/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.MapResult;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.HashMap;
import java.util.Map;

/**
 * AfterProbe implementation that analyzes DTLS retransmission behavior by counting retransmitted
 * handshake messages and storing the results in the scan report.
 *
 * @param <ReportT> the type of TLS scan report this probe operates on
 */
public class DtlsRetransmissionAfterProbe<ReportT extends TlsScanReport>
        extends AfterProbe<ReportT> {

    /**
     * Analyzes DTLS retransmission data by extracting retransmitted handshake messages from the
     * report, counting occurrences of each message type, and storing both the per-type counters and
     * total retransmission count in the report.
     *
     * @param report the TLS scan report containing extracted DTLS retransmission data
     */
    @Override
    public void analyze(ReportT report) {
        ExtractedValueContainer<HandshakeMessageType> container =
                report.getExtractedValueContainer(
                        TrackableValueType.DTLS_RETRANSMISSIONS, HandshakeMessageType.class);

        Map<HandshakeMessageType, Integer> retransmissionCounters = new HashMap<>();
        for (HandshakeMessageType type : container.getExtractedValueList()) {
            if (!retransmissionCounters.containsKey(type)) {
                retransmissionCounters.put(type, 1);
            } else {
                retransmissionCounters.put(type, retransmissionCounters.get(type) + 1);
            }
        }
        report.putResult(
                TlsAnalyzedProperty.MAP_RETRANSMISSION_COUNTERS,
                new MapResult<>(
                        TlsAnalyzedProperty.MAP_RETRANSMISSION_COUNTERS, retransmissionCounters));
        report.putResult(
                TlsAnalyzedProperty.TOTAL_RECEIVED_RETRANSMISSIONS,
                container.getNumberOfExtractedValues());
    }
}
