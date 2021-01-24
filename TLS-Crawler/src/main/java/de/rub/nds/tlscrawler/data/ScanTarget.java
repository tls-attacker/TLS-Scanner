/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Scan target implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
@Getter
@AllArgsConstructor
public class ScanTarget implements Serializable {

    private final String ip;
    private final String hostname;
    private final int port;

}
