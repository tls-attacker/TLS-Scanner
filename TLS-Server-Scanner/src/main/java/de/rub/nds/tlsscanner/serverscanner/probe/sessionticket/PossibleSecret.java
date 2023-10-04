/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import de.rub.nds.tlsscanner.core.util.ArrayUtil;
import java.io.Serializable;

public class PossibleSecret implements Serializable {
    public enum Secret {
        PREMASTER_SECRET,
        HANDSHAKE_SECRET,
        RESUMPTION_SECRET,
        MASTER_SECRET,
        PRESHARED_KEY,
    }

    public final Secret secretType;
    public final byte[] value;

    public PossibleSecret(Secret secret, byte[] value) {
        this.secretType = secret;
        this.value = value;
    }

    public boolean isContainedIn(byte[] haystack) {
        return ArrayUtil.findSubarray(haystack, value) != -1;
    }
}
