/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 */
package de.rub.nds.tlsscanner.probe.mac;

/**
 *
 * @author robert
 */
public enum ByteCheckStatus {
    CHECKED, NOT_CHECKED, CHECKED_WITH_FIN
}
