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
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

@XmlRootElement()
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientReport extends Observable implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final char[] UID_ALPH = "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final int UID_LEN = 10; // 36^10 > 2^50; that should be large enough
    private static final Set<String> usedUIDs = new HashSet<>();
    private static final Random uidRandom = new Random();

    private final Map<Class<? extends IProbe>, ClientProbeResult> resultMap;
    private final Collection<String> genericWarnings;
    private final ClientInfo clientInfo;
    public final transient String uid;

    private static String generateUID() {
        char[] uidArr = new char[UID_LEN];
        String uid;
        do {
            for (int i = 0; i < uidArr.length; i++) {
                uidArr[i] = UID_ALPH[uidRandom.nextInt(UID_ALPH.length)];
            }
            uid = new String(uidArr);
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

    public Map<Class<? extends IProbe>, ClientProbeResult> getResultMap() {
        return resultMap;
    }

    public boolean hasResult(Class<? extends IProbe> clazz) {
        return resultMap.containsKey(clazz);
    }

    public ClientProbeResult getResult(Class<? extends IProbe> clazz) {
        return resultMap.get(clazz);
    }

    public <T extends ClientProbeResult> T getResult(Class<? extends IProbe> clazz, Class<T> expectedReturnType) {
        // convenience function
        try {
            return expectedReturnType.cast(getResult(clazz));
        } catch (ClassCastException e) {
            return null;
        }
    }

    public ClientProbeResult putResult(Class<? extends IProbe> clazz, ClientProbeResult result) {
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