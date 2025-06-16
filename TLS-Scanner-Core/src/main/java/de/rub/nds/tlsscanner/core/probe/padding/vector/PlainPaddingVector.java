/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding.vector;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.Objects;

public class PlainPaddingVector extends PaddingVector {

    private final ByteArrayExplicitValueModification modification;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private PlainPaddingVector() {
        super(null, null);
        this.modification = null;
    }

    public PlainPaddingVector(
            String name, String identifier, ByteArrayExplicitValueModification modification) {
        super(name, identifier);
        this.modification = modification;
    }

    @Override
    public Record createRecord() {
        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray byteArray = new ModifiableByteArray();
        byteArray.setModifications(modification);
        r.getComputations().setPlainRecordBytes(byteArray);
        return r;
    }

    @Override
    public int getRecordLength(
            CipherSuite testedSuite, ProtocolVersion testedVersion, int appDataLength) {
        Record r = createRecord();
        r.getComputations().setPlainRecordBytes(new byte[appDataLength]);
        int size = r.getComputations().getPlainRecordBytes().getValue().length;
        return size;
    }

    public ByteArrayExplicitValueModification getModification() {
        return modification;
    }

    @Override
    public String toString() {
        return "" + name + "{" + "modification=" + modification + '}';
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 11 * hash + Objects.hashCode(this.modification);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final PlainPaddingVector other = (PlainPaddingVector) obj;
        return Objects.equals(this.modification, other.modification);
    }
}
