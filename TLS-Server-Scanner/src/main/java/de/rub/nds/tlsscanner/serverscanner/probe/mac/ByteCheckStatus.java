/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/*
 */

package de.rub.nds.tlsscanner.serverscanner.probe.mac;

/**
 *
 * @author robert
 */
public enum ByteCheckStatus {
    CHECKED,
    NOT_CHECKED,
    CHECKED_WITH_FIN,
    ERROR_DURING_TEST
}
