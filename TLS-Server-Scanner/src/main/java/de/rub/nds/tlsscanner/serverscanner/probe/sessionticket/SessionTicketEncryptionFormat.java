/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import com.beust.jcommander.ParameterException;
import de.rub.nds.scanner.core.config.ScannerDetail;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class SessionTicketEncryptionFormat implements Serializable {
    /**
     * Standard offsets of ciphertext after IV/Nonce. RFC 5077 recommends 2 bytes for a length
     * field. But many implementations ignore this.
     */
    private static final Integer[] STANDARD_CIPHERTEXT_OFFSETS = {0, 2};
    /**
     * minimum secret size is 32 byte. The ticket should at least be large enough to contain this
     */
    private static final int MIN_TICKET_SIZE = 32;

    private static final int STATE_OFFSET_MAX_NORMAL = 32;
    private static final int STATE_OFFSET_MAX_DETAILED = 128;

    public static List<SessionTicketEncryptionFormat> generateFormats(
            ScannerDetail scannerDetail, int ticketLength, int ivLength, int keynameLengthHint) {

        Set<Integer> ivOffsets = new HashSet<>();
        Set<Integer> ciphertextOffsets = new HashSet<>();
        ciphertextOffsets.addAll(Arrays.asList(STANDARD_CIPHERTEXT_OFFSETS));

        if (scannerDetail.getLevelValue() >= ScannerDetail.QUICK.getLevelValue()) {
            ivOffsets.add(0); // was applicable in the wild to CBC
            ivOffsets.add(4); // mbedTLS
            ivOffsets.add(16); // RFC 5077, OpenSSL, BoringSSL
            ivOffsets.add(28); // Botan
            ivOffsets.add(keynameLengthHint);
            ivOffsets.add(keynameLengthHint - ivLength);
        }

        if (scannerDetail.getLevelValue() >= ScannerDetail.NORMAL.getLevelValue()) {
            for (int i = 0; i < STATE_OFFSET_MAX_NORMAL; i++) {
                ivOffsets.add(i);
                ivOffsets.add(keynameLengthHint + i);
            }
        }

        if (scannerDetail.getLevelValue() >= ScannerDetail.DETAILED.getLevelValue()) {
            for (int i = 0; i < STATE_OFFSET_MAX_DETAILED; i++) {
                ivOffsets.add(i);
                ivOffsets.add(keynameLengthHint + i);
            }
        }

        if (scannerDetail.getLevelValue() >= ScannerDetail.ALL.getLevelValue()) {
            for (int i = 0; i < ticketLength - MIN_TICKET_SIZE; i++) {
                ivOffsets.add(i);
            }
        }

        int maxOffset = ticketLength - ivLength - MIN_TICKET_SIZE;
        ivOffsets.removeIf(x -> x < 0);
        ivOffsets.removeIf(x -> x > maxOffset);

        List<SessionTicketEncryptionFormat> ret = new ArrayList<>(ivOffsets.size());
        for (int ivOffset : ivOffsets) {
            for (int ciphertextOffset : ciphertextOffsets) {
                ret.add(new SessionTicketEncryptionFormat(ivOffset, ivLength, ciphertextOffset));
            }
        }
        // add all offsets that use zero IVs
        // we first deduplicate the positions
        // e.g. ivoffset=2 cipheroffset=2 is the same as ivoffset=4 cipheroffset=0
        Set<Integer> zeroIvOffsets = new HashSet<>();
        zeroIvOffsets.addAll(ivOffsets);
        for (int ciphertextOffset : ciphertextOffsets) {
            zeroIvOffsets.addAll(
                    ivOffsets.stream().map(i -> i + ciphertextOffset).collect(Collectors.toList()));
        }
        for (int zeroIvOffset : zeroIvOffsets) {
            ret.add(new SessionTicketEncryptionFormat(ivLength, zeroIvOffset));
        }
        return ret;
    }

    /** Offset where the IV/Nonce start (from the left) */
    private final int ivNonceOffset;
    /** Length of the IV/Nonce */
    private final int ivNonceLength;
    /** Offset of the ciphertext from the IV */
    private final int ciphertextOffset;
    /** Whether to assume a zero IV which is not included in the format itself */
    private final boolean zeroIvNonce;

    public SessionTicketEncryptionFormat(
            int ivNonceOffset, int ivNonceLength, int ciphertextOffset, boolean zeroIvNonce) {
        if (zeroIvNonce && ivNonceOffset != 0) {
            throw new ParameterException("For a zero IV/Nonce the IV/Nonce offset has to be 0");
        }
        this.ivNonceOffset = ivNonceOffset;
        this.ivNonceLength = ivNonceLength;
        this.ciphertextOffset = ciphertextOffset;
        this.zeroIvNonce = zeroIvNonce;
    }

    public SessionTicketEncryptionFormat(
            int ivNonceOffset, int ivNonceLength, int ciphertextOffset) {
        this(ivNonceOffset, ivNonceLength, ciphertextOffset, false);
    }

    public SessionTicketEncryptionFormat(int ivNonceLength, int ciphertextOffset) {
        this(0, ivNonceLength, ciphertextOffset, true);
    }

    public int getIvNonceLength() {
        return ivNonceLength;
    }

    public int getIvNonceOffset() {
        return ivNonceOffset;
    }

    public int getCiphertextOffset() {
        return ciphertextOffset;
    }

    public boolean isZeroIvNonce() {
        return zeroIvNonce;
    }

    public byte[] getIvNonce(byte[] ticketBytes) {
        if (zeroIvNonce) {
            return new byte[ivNonceLength];
        } else {
            return Arrays.copyOfRange(ticketBytes, ivNonceOffset, ivNonceOffset + ivNonceLength);
        }
    }

    /**
     * Get the ciphertext truncated to match the blocksize.
     *
     * @param ticketBytes bytes to extract ciphertext from
     * @param blocksize blocksize of the cipher to use; returned ciphertext will be splittable into
     *     this blocksize
     * @return ciphertext truncated such that it has a length that is a multiple of the blocksize
     */
    public byte[] getCiphertextTruncated(byte[] ticketBytes, int blocksize) {
        if (blocksize < 1) {
            throw new IllegalArgumentException("blocksize needs to be at least 1");
        }
        int retStart = ivNonceOffset + ciphertextOffset;
        if (!zeroIvNonce) {
            retStart += ivNonceLength;
        }

        int cipherLength = ticketBytes.length - retStart;
        int retLength = cipherLength - (cipherLength % blocksize);
        return Arrays.copyOfRange(ticketBytes, retStart, retStart + retLength);
    }

    @Override
    public String toString() {
        if (zeroIvNonce) {
            return String.format(
                    "IV/Nonce=00 Ciphertext@%d (IV/Nonce length=%d)",
                    ciphertextOffset, ivNonceLength);
        } else {
            return String.format(
                    "IV/Nonce@%d Ciphertext@+%d (IV/Nonce length=%d)",
                    ivNonceOffset, ciphertextOffset, ivNonceLength);
        }
    }
}
