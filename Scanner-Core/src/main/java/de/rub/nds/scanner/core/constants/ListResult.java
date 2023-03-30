/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.constants;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

/**
 * Represents {@link TestResult}s of type {@link List} with objects of type T.
 *
 * @param <T> the type of the list elements.
 */
@XmlRootElement(name = "result")
@XmlAccessorType(XmlAccessType.FIELD)
public class ListResult<T> extends CollectionResult<T> {

    /**
     * The constructor for the ListResult. Use property.name() for the name parameter.
     *
     * @param list the list of the ListResult.
     * @param name the name of the ListResult.
     */
    public ListResult(List<T> list, String name) {
        super(list, name);
    }

    /**
     * @return the list of the listResult object.
     */
    public List<T> getList() {
        return (List<T>) collection;
    }
}
