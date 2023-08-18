/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.response;

public enum EqualityError {

    /** */
    NONE,
    /** */
    SOCKET_STATE,
    /** */
    MESSAGE_COUNT,
    /** */
    RECORD_COUNT,
    /** */
    RECORD_CLASS,
    /** */
    MESSAGE_CLASS,
    /** */
    MESSAGE_CONTENT,
    /** */
    RECORD_CONTENT_TYPE,
    /** */
    RECORD_LENGTH,
    /** */
    RECORD_VERSION,
    /** */
    RECORD_CONTENT;
}
