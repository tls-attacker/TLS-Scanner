/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
