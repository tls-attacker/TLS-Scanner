/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class SessionTicketAfterStats implements Serializable {
    private Map<Integer, Integer> ticketLengthOccurences;
    private Integer keyNameLength = null;
    private List<String> asciiStringsFound;

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
        for (Entry<Integer, Integer> entry :
                ticketLengthOccurences.entrySet().stream()
                        .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                        .toArray(Entry[]::new)) {
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
}
