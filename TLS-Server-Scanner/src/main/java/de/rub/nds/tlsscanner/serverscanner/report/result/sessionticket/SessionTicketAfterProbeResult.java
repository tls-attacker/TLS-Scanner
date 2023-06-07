/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.fasterxml.jackson.annotation.JsonProperty;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.PossibleSecret;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionDependentResult;

public class SessionTicketAfterProbeResult extends VersionDependentResult {
    private Map<Integer, Integer> ticketLengthOccurences;
    private Integer keyNameLength = null;
    private List<String> asciiStringsFound;
    private PossibleSecret containsPlainSecret;
    private PossibleSecret discoveredReusedKeystream;

    private FoundDefaultStek foundDefaultStek = null;
    private FoundDefaultHmacKey foundDefaultHmacKey = null;

    public SessionTicketAfterProbeResult(@JsonProperty("protocolVersion") ProtocolVersion protocolVersion) {
        super(protocolVersion);
    }

    public Map<Integer, Integer> getTicketLengthOccurences() {
        return ticketLengthOccurences;
    }

    public void setTicketLengthOccurences(Map<Integer, Integer> ticketLengthOccurences) {
        this.ticketLengthOccurences = ticketLengthOccurences;
    }

    public String getTicketLengths() {
        if (ticketLengthOccurences == null) {
            return null;
        }

        StringBuilder ret = new StringBuilder();
        for (Entry<Integer, Integer> entry : ticketLengthOccurences.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue())).toArray(Entry[]::new)) {
            ret.append(entry.getKey());
            ret.append("(x");
            ret.append(entry.getValue());
            ret.append("), ");
        }
        // remove trailing comma
        if (ret.length() > 2) {
            ret.delete(ret.length() - 2, ret.length() - 1);
        }
        return ret.toString();
    }

    public Integer getKeyNameLength() {
        return this.keyNameLength;
    }

    public void setKeyNameLength(int keyNameLength) {
        this.keyNameLength = keyNameLength;
    }

    public List<String> getAsciiStringsFound() {
        if (asciiStringsFound == null) {
            return Collections.emptyList();
        }
        return asciiStringsFound;
    }

    public void setAsciiStringsFound(List<String> asciiStringsFound) {
        this.asciiStringsFound = asciiStringsFound;
    }

    public String getAsciiStringsFoundCollapsed() {
        if (asciiStringsFound == null) {
            return null;
        }
        StringBuilder ret = new StringBuilder();
        for (String str : asciiStringsFound) {
            ret.append(str);
            ret.append(", ");
        }
        // remove trailing comma
        if (ret.length() > 2) {
            ret.delete(ret.length() - 2, ret.length() - 1);
        }
        return ret.toString();
    }

    public PossibleSecret getContainsPlainSecret() {
        return this.containsPlainSecret;
    }

    public void setContainsPlainSecret(PossibleSecret containsPlainSecret) {
        this.containsPlainSecret = containsPlainSecret;
    }

    public FoundDefaultStek getFoundDefaultStek() {
        return this.foundDefaultStek;
    }

    public void setFoundDefaultStek(FoundDefaultStek foundDefaultStek) {
        this.foundDefaultStek = foundDefaultStek;
    }

    public FoundDefaultHmacKey getFoundDefaultHmacKey() {
        return this.foundDefaultHmacKey;
    }

    public void setFoundDefaultHmacKey(FoundDefaultHmacKey foundDefaultHmacKey) {
        this.foundDefaultHmacKey = foundDefaultHmacKey;
    }

    public PossibleSecret getDiscoveredReusedKeystream() {
        return this.discoveredReusedKeystream;
    }

    public void setDiscoveredReusedKeystream(PossibleSecret discoveredReusedKeystream) {
        this.discoveredReusedKeystream = discoveredReusedKeystream;
    }

    @Override
    public void writeToSiteReport(SiteReport report) {
        report.putSessionTicketAfterProbeResult(protocolVersion, this);
        putResult(report, AnalyzedProperty.UNENCRYPTED_TICKET, containsPlainSecret != null, true);
        putResult(report, AnalyzedProperty.DEFAULT_ENCRYPTION_KEY_TICKET, foundDefaultStek != null, true);
        putResult(report, AnalyzedProperty.DEFAULT_HMAC_KEY_TICKET, foundDefaultHmacKey != null, true);
    }
}
