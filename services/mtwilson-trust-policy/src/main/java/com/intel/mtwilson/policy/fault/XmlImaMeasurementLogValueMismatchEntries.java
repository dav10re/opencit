/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.policy.fault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.model.Measurement;
import com.intel.mtwilson.model.PcrIndex;
import com.intel.mtwilson.policy.Fault;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author jbuhacoff
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class XmlImaMeasurementLogValueMismatchEntries extends Fault {
    private PcrIndex pcrIndex;
    private List<Measurement> mismatchEntries;
    
    // for deserializing jackson
    public XmlImaMeasurementLogValueMismatchEntries() {
        mismatchEntries = new ArrayList<>();
    } 
    
    public XmlImaMeasurementLogValueMismatchEntries(PcrIndex pcrIndex, List<Measurement> mismatchEntries) {
        super("XML measurement log for PCR %d contains %d entries for which the values are modified.", pcrIndex.toInteger(), mismatchEntries.size());
        this.pcrIndex = pcrIndex;
        this.mismatchEntries = mismatchEntries;
    }
    
    public PcrIndex getPcrIndex() { return pcrIndex; }
    public List<Measurement> getMismatchEntries() { return mismatchEntries; }
}
