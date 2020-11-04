/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result.statistics;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public enum CookieEvaluationResult {
    NO_DUPLICATES,
    DUPLICATES,
    NOT_ANALYZED
}
