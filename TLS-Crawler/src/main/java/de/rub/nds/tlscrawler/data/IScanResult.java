/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.tlscrawler.utility.ITuple;

import java.time.Instant;
import java.util.List;

/**
 * Scan result interface. Build to ensure compatibility with MongoDB, i. e. BSON.
 * Will also be helpful in other DB-implementations, since it clearly defines
 * allowed data types in results.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IScanResult {

    /**
     * IScanResults need to have an ID as well, so they can be identified, i. e. matched with the
     * scan that produced them. This key ought to be used canonically.
     */
    String ID_KEY = "_result_id";

    /**
     * Should canonically be referred to to determine which scan added this result structure.
     * Should be required to be set for every result structure, even substructures.
     *
     * @param identifier The identifier for this result. In top-level results this should be the fully qualified scan name.
     */
    void setResultIdentifier(String identifier);

    /**
     * Adds a string value to the result structure.
     *
     * @param key The value's key.
     * @param value The value.
     */
    void addString(String key, String value);

    /**
     * Adds a string array to the result structure.
     *
     * @param key The array's key.
     * @param value The array.
     */
    void addStringArray(String key, List<String> value);

    /**
     * Adds a long value to the result structure.
     *
     * @param key The value's key.
     * @param value The value.
     */
    void addLong(String key, Long value);

    /**
     * Adds a long array to the result structure.
     *
     * @param key The arrays's key.
     * @param value The array.
     */
    void addLongArray(String key, List<Long> value);

    /**
     * Adds an integer value to the result structure.
     *
     * @param key The value's key.
     * @param value The value.
     */
    void addInteger(String key, Integer value);

    /**
     * Adds an integer array to the result structure.
     *
     * @param key The arrays's key.
     * @param value The array.
     */
    void addIntegerArray(String key, List<Integer> value);

    /**
     * Adds a double value to the result structure.
     *
     * @param key The value's key.
     * @param value The value.
     */
    void addDouble(String key, Double value);

    /**
     * Adds a double array to the result structure.
     *
     * @param key The array's key.
     * @param value The array.
     */
    void addDoubleArray(String key, List<Double> value);

    /**
     * Adds a timestamp value to the result structure.
     *
     * @param key The value's key.
     * @param value The value.
     */
    void addTimestamp(String key, Instant value);

    /**
     * Adds binary data to the result structure.
     *
     * @param key The data's key.
     * @param data The binary data.
     */
    void addBinaryData(String key, List<Byte> data);

    /**
     * Adds an IScanResult to this result to allow nesting results.
     *
     * @param key The sub-result's key.
     * @param substructure The sub-result.
     */
    void addSubResult(String key, IScanResult substructure);

    /**
     * Returns the result data.
     *
     * @return A list of result data tuples.
     */
    List<ITuple<String, Object>> getContents();
}
