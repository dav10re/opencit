/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.agent;

import com.intel.mtwilson.datatypes.TxtHostRecord;
import com.intel.mtwilson.model.Aik;
import com.intel.mtwilson.model.Nonce;
import com.intel.mtwilson.model.PcrIndex;
import com.intel.mtwilson.model.PcrManifest;
import com.intel.mtwilson.model.TpmQuote;
import com.intel.mtwilson.trustagent.model.VMAttestationResponse;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.mtwilson.trustagent.model.VMAttestationRequest;
import com.intel.mtwilson.trustagent.model.VMQuoteResponse;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;

/**
 * 
 * 
 * @author dav10re
 */
public interface HostAgentForIma extends HostAgent {

    
    
   
    PcrManifest getPcrManifest(boolean ima) throws IOException;

    PcrManifest getPcrManifest(Nonce challenge, boolean ima) throws IOException;
    
    
}
