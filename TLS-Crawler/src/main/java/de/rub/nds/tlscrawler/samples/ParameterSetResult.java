/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.samples;

import java.util.ArrayList;
import java.util.List;

public class ParameterSetResult {
    
    private boolean showsNotValidated;
    private boolean showsKeyReuse;
    private boolean showsVulnerability;
    private List<String> uniqueFingerprints;
    
    public ParameterSetResult() {
        uniqueFingerprints = new ArrayList<>();
    }
    
    public ParameterSetResult(boolean showsNotValidated, boolean showsKeyReuse, boolean showsVulnerability, List<String> uniqueFingerprints) {
        this.showsNotValidated = showsNotValidated;
        this.showsKeyReuse = showsKeyReuse;
        this.uniqueFingerprints = uniqueFingerprints;
    }
    
    public boolean containsFingerprint(String fingerprint) {
        for(String fp: getUniqueFingerprints()) {
            if(fingerprint.equals(fp)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return the showsNotValidated
     */
    public boolean isShowsNotValidated() {
        return showsNotValidated;
    }

    /**
     * @param showsNotValidated the showsNotValidated to set
     */
    public void setShowsNotValidated(boolean showsNotValidated) {
        this.showsNotValidated = showsNotValidated;
    }

    /**
     * @return the showsKeyReuse
     */
    public boolean isShowsKeyReuse() {
        return showsKeyReuse;
    }

    /**
     * @param showsKeyReuse the showsKeyReuse to set
     */
    public void setShowsKeyReuse(boolean showsKeyReuse) {
        this.showsKeyReuse = showsKeyReuse;
    }

    /**
     * @return the uniqueFingerprints
     */
    public List<String> getUniqueFingerprints() {
        return uniqueFingerprints;
    }

    /**
     * @param uniqueFingerprints the uniqueFingerprints to set
     */
    public void setUniqueFingerprints(List<String> uniqueFingerprints) {
        this.uniqueFingerprints = uniqueFingerprints;
    }

    /**
     * @return the showsVulnerability
     */
    public boolean isShowsVulnerability() {
        return showsVulnerability;
    }

    /**
     * @param showsVulnerability the showsVulnerability to set
     */
    public void setShowsVulnerability(boolean showsVulnerability) {
        this.showsVulnerability = showsVulnerability;
    }
    
    public boolean fingerprintsLookSimialar(ParameterSetResult otherResult) {
        List<String> otherUniqueFingerprints = otherResult.getUniqueFingerprints();
        if(otherUniqueFingerprints.size() != uniqueFingerprints.size()) {
            return false;
        } else {
            for(String otherFp: otherUniqueFingerprints) {
                boolean seenForBoth = false;
                for(String myFp: uniqueFingerprints) {
                    if(myFp.equals(otherFp)) {
                        seenForBoth = true;
                        break;
                    }
                }
                if(!seenForBoth) {
                    return false;
                }
            }
            
            return true;
        }
        
    }
}
