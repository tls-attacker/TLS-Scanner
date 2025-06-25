/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.response;

/** Enum representing different types of equality errors when comparing response fingerprints. */
public enum EqualityError {

    /** No difference found between fingerprints */
    NONE,
    /** Socket state differs between fingerprints */
    SOCKET_STATE,
    /** Number of messages differs between fingerprints */
    MESSAGE_COUNT,
    /** Number of records differs between fingerprints */
    RECORD_COUNT,
    /** Record class types differ between fingerprints */
    RECORD_CLASS,
    /** Message class types differ between fingerprints */
    MESSAGE_CLASS,
    /** Message content differs between fingerprints */
    MESSAGE_CONTENT,
    /** Record content type differs between fingerprints */
    RECORD_CONTENT_TYPE,
    /** Record length differs between fingerprints */
    RECORD_LENGTH,
    /** Record version differs between fingerprints */
    RECORD_VERSION,
    /** Record content differs between fingerprints */
    RECORD_CONTENT;
}
