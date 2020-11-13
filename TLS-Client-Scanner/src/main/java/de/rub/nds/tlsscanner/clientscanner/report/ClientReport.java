/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.report;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Observable;
import java.util.Random;
import java.util.Set;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;
import de.rub.nds.tlsscanner.clientscanner.probe.Probe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.RandString;

@XmlRootElement()
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientReport extends Observable implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final char[] UID_ALPH = "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final int UID_LEN = 10; // 36^10 > 2^50; that should be large
                                           // enough
    private static final Set<String> usedUIDs = new HashSet<>();
    private static final Random uidRandom = new Random();

    private final Map<Class<? extends Probe>, ClientProbeResult> resultMap;
    private final Collection<String> genericWarnings;
    private final ClientInfo clientInfo;
    public final transient String uid;

    private static String generateUID() {
        String uid;
        do {
            uid = RandString.getRandomString(UID_LEN, UID_ALPH);
        } while (!usedUIDs.add(uid));
        return uid;
    }

    private ClientReport() {
        // for serialization
        clientInfo = null;
        resultMap = null;
        genericWarnings = null;
        uid = null;
    }

    public ClientReport(ClientInfo clientInfo) {
        this.resultMap = new HashMap<>();
        this.genericWarnings = new ArrayList<>();
        this.clientInfo = clientInfo;
        uid = generateUID();
    }

    public void finalizeReport() {
        usedUIDs.remove(uid);
    }

    public Map<Class<? extends Probe>, ClientProbeResult> getResultMap() {
        return resultMap;
    }

    public boolean hasResult(Class<? extends Probe> clazz) {
        return resultMap.containsKey(clazz);
    }

    public ClientProbeResult getResult(Class<? extends Probe> clazz) {
        return resultMap.get(clazz);
    }

    public <T extends ClientProbeResult> T getResult(Class<? extends Probe> clazz, Class<T> expectedReturnType) {
        // convenience function
        try {
            return expectedReturnType.cast(getResult(clazz));
        } catch (ClassCastException e) {
            return null;
        }
    }

    public ClientProbeResult putResult(Class<? extends Probe> clazz, ClientProbeResult result) {
        ClientProbeResult ret = resultMap.put(clazz, result);
        markAsChangedAndNotify();
        return ret;
    }

    public void addGenericWarning(String warning) {
        genericWarnings.add(warning);
    }

    public synchronized void markAsChangedAndNotify() {
        this.setChanged();
        this.notifyObservers();
    }

}