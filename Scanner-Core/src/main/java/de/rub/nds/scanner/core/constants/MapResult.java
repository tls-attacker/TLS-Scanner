/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.constants;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Map;

/**
 * Represents {@link TestResult}s of type {@link Map} with pairs of type S and T.
 *
 * @param <S> the key types of the map.
 * @param <T> the value types of the map.
 */
@XmlRootElement(name = "result")
@XmlAccessorType(XmlAccessType.FIELD)
public class MapResult<S, T> extends CollectionResult<S> {

    private final Map<S, T> map;

    /**
     * The constructor for the MapResult. Use property.name() for the name parameter.
     *
     * @param map the map.
     * @param name the name of the MapResult.
     */
    public MapResult(Map<S, T> map, String name) {
        super(map.keySet(), name);
        this.map = map;
    }

    /**
     * @return the map of the MapResult object.
     */
    public Map<S, T> getMap() {
        return map;
    }
}
