/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.HashMap;
import java.util.Map;

public class DtlsRetransmissionAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        ExtractedValueContainer<HandshakeMessageType> container =
            report.getExtractedValueContainerMap().get(TrackableValueType.DTLS_RETRANSMISSIONS);

        Map<HandshakeMessageType, Integer> retransmissionCounters = new HashMap<>();
        for (HandshakeMessageType type : container.getExtractedValueList()) {
            if (!retransmissionCounters.containsKey(type)) {
                retransmissionCounters.put(type, 1);
            } else {
                retransmissionCounters.put(type, retransmissionCounters.get(type) + 1);
            }
        }

        report.setRetransmissionCounters(retransmissionCounters);
        report.setTotalReceivedRetransmissions(container.getNumberOfExtractedValues());
    }

}
