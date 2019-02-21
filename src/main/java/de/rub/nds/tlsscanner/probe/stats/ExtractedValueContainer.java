/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.stats;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class ExtractedValueContainer<T> {

    private final List<T> extractedValueList;

    private final TrackableValueType type;

    public ExtractedValueContainer(TrackableValueType type) {
        extractedValueList = new LinkedList<>();
        this.type = type;
    }

    public boolean areAllValuesIdentical() {
        if (extractedValueList.size() > 0) {
            T t = extractedValueList.get(0);
            for (int i = 1; i < extractedValueList.size(); i++) {
                if (!extractedValueList.get(i).equals(t)) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean areAllValuesDiffernt() {
        Set<T> set = new HashSet<>();
        set.addAll(extractedValueList);
        return set.size() == extractedValueList.size();
    }

    public List<T> getExtractedValueList() {
        return extractedValueList;
    }

    public int getNumberOfExtractedValues() {
        return extractedValueList.size();
    }

    public void put(T t) {
        extractedValueList.add(t);
    }

    public TrackableValueType getType() {
        return type;
    }
}
