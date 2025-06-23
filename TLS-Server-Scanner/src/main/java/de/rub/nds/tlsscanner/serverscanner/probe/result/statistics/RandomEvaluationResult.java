/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.statistics;

/** Represents the result of evaluating randomness in server responses or generated values. */
public enum RandomEvaluationResult {
    /** No duplicate values were found in the analyzed data */
    NO_DUPLICATES,
    /** Duplicate values were detected in the analyzed data */
    DUPLICATES,
    /** The data appears to be based on Unix timestamp values */
    UNIX_TIME,
    /** The data does not exhibit random characteristics */
    NOT_RANDOM,
    /** The data was not analyzed for randomness */
    NOT_ANALYZED
}
