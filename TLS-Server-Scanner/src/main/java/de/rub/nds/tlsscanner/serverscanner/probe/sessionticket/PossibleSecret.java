/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

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
        for (int offset = 0; offset < haystack.length - value.length; offset++) {
            if (haystack[offset] == value[0]) {

                boolean difference = false;
                // check if needle starts here
                for (int i = 0; i < value.length; i++) {
                    if (haystack[offset + i] != value[i]) {
                        difference = true;
                        break;
                    }
                }
                if (!difference) {
                    return true;
                }

            }
        }
        return false;
    }

}
