/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.as.business;

import com.intel.mtwilson.i18n.ErrorCode;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.My;
import com.intel.mtwilson.agent.HostAgent;
import com.intel.mtwilson.agent.HostAgentFactory;
import com.intel.mtwilson.as.controller.TblHostSpecificManifestJpaController;
import com.intel.mtwilson.as.controller.TblHostsJpaController;
import com.intel.mtwilson.as.controller.TblMleJpaController;
import com.intel.mtwilson.as.controller.TblSamlAssertionJpaController;
import com.intel.mtwilson.as.controller.TblTaLogJpaController;
import com.intel.mtwilson.as.controller.exceptions.IllegalOrphanException;
import com.intel.mtwilson.as.controller.exceptions.NonexistentEntityException;
import com.intel.mtwilson.as.data.MwAssetTagCertificate;
import com.intel.mtwilson.as.data.TblHostSpecificManifest;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblModuleManifest;
import com.intel.mtwilson.as.data.TblSamlAssertion;
import java.io.IOException;
import com.intel.mtwilson.as.data.TblTaLog;
import com.intel.mtwilson.as.ASComponentFactory;
import com.intel.mtwilson.as.BaseBO;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.SimpleKeystore;
import com.intel.dcsg.cpg.io.Resource;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.datatypes.*;
import com.intel.dcsg.cpg.jpa.PersistenceManager;
import com.intel.mtwilson.model.*;
import com.intel.mtwilson.model.PcrIndex;
import com.intel.mtwilson.util.ResourceFinder;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.Object;
import java.net.MalformedURLException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * All settings should be via setters, not via constructor, because this class
 * may be instantiated by a factory.
 *
 * @author dsmagadx
 */
public class HostBO extends BaseBO {

	private static final String COMMAND_LINE_MANIFEST = "/b.b00 vmbTrustedBoot=true tboot=0x0x101a000";
	public static final PcrIndex LOCATION_PCR = PcrIndex.PCR22;
        private Logger log = LoggerFactory.getLogger(getClass());
        private TblMle biosMleId = null;
        private TblMle vmmMleId = null;
//        private byte[] dataEncryptionKey = null;
//        private TblLocationPcrJpaController locationPcrJpaController = new TblLocationPcrJpaController(getEntityManagerFactory());
//        private TblMleJpaController mleController = new TblMleJpaController(getEntityManagerFactory());
//        private TblHostsJpaController hostController = new TblHostsJpaController(getEntityManagerFactory());
//        private HostTrustPolicyManager hostTrustPolicyFactory = new HostTrustPolicyManager(getEntityManagerFactory());
//        private TblHostSpecificManifestJpaController hostSpecificManifestJpaController = new TblHostSpecificManifestJpaController(getEntityManagerFactory());
//        private TblModuleManifestJpaController moduleManifestJpaController = new TblModuleManifestJpaController(getEntityManagerFactory());


        /*
        public void setDataEncryptionKey(byte[] key) {
                    try {
                        TblHosts.dataCipher = new Aes128DataCipher(new Aes128(key));
                    }
                    catch(CryptographyException e) {
                        log.error("Cannot initialize data encryption cipher", e);
                    }      
        }*/
        
    public HostBO()  {
        
        super();
       
   
    }
    
    public HostBO(PersistenceManager pm) {
        super(pm);
       
    }
        
	public HostResponse addHost(TxtHost host, PcrManifest pcrManifest, HostAgent agent, String uuid, Object... tlsObjects) {
            
           System.err.println("HOST BO ADD HOST STARTING");
            

                try {
                    
          TblMle  biosMleId = findBiosMleForHost(host); 
          TblMle  vmmMleId = findVmmMleForHost(host); 
          Vendor hostType;

                log.trace("HOST BO ADD HOST STARTING");
                    
                        checkForDuplicate(host);

                        getBiosAndVMM(host);

                        log.debug("Getting Server Identity.");

                        // BUG #497  setting default tls policy name and empty keystore for all new hosts. XXX TODO allow caller to provide keystore contents in pem format in the call ( in the case of the other tls policies ) or update later
                        TblHosts tblHosts = new TblHosts();

			String tlsPolicyName = tlsObjects.length > 0 ? (String)tlsObjects[0] : My.configuration().getDefaultTlsPolicyName();
	    		String[] tlsCertificates = tlsObjects.length > 1 ? (String[])tlsObjects[1] : new String[1];
                        tblHosts.setTlsPolicyName(tlsPolicyName);

			Resource resource = tblHosts.getTlsKeystoreResource();
                        SimpleKeystore clientKeystore = new SimpleKeystore(resource, My.configuration().getTlsKeystorePassword());
			if (tlsCertificates != null) {
	                        for (String certificate : tlsCertificates) {
        	                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                	            X509Certificate x509Cert = X509Util.decodePemCertificate(new String(Base64.decodeBase64(certificate)));
                        	    clientKeystore.addTrustedSslCertificate(x509Cert, host.getHostName().toString());
	                        }
			}
                        clientKeystore.save();
                        //tblHosts.setTlsKeystore(null);
                        //System.err.println("stdalex addHost " + host.getHostName() + " with cs == " + host.getAddOn_Connection_String());
                        tblHosts.setAddOnConnectionInfo(host.getAddOn_Connection_String());
                        
                        // Using the connection string we will find out the type of the host. This information would be used later
                        ConnectionString hostConnString = new ConnectionString(host.getAddOn_Connection_String());
                        hostType = hostConnString.getVendor();
                        
                        if (host.getHostName() != null) {
                                tblHosts.setName(host.getHostName().toString());
                        }
                        if (host.getHostName() != null) {
                                tblHosts.setIPAddress(host.getHostName().toString());
                        }
                        if (host.getPort() != null) {
                                tblHosts.setPort(host.getPort());
                        }

                        if (agent == null) {
                            HostAgentFactory factory = new HostAgentFactory();
                            agent = factory.getHostAgent(tblHosts);
                        }

                        if( agent.isAikAvailable() ) { // INTEL and CITRIX
                            PublicKey publicKey = agent.getAik();
                            String publicKeySha1 = Sha1Digest.valueOf(publicKey.getEncoded()).toString();
                            if (My.jpa().mwHosts().findByAikPublicKeySha1(publicKeySha1) != null) {
                                throw new ASException(ErrorCode.AS_DUPLICATE_AIK_PUBLIC_KEY, publicKeySha1);
                            }

                                // stores the AIK public key (and certificate, if available) in the host record, and sets AIK_SHA1=SHA1(AIK_PublicKey) on the host record too
                                setAikForHost(tblHosts, host, agent); 
                                // Intel hosts return an X509 certificate for the AIK public key, signed by the privacy CA.  so we must verify the certificate is ok.
                                if( agent.isAikCaAvailable() ) {
                                    // we have to check that the aik certificate was signed by a trusted privacy ca
                                    X509Certificate hostAikCert = X509Util.decodePemCertificate(tblHosts.getAIKCertificate());
                                    hostAikCert.checkValidity(); // AIK certificate must be valid today
                                    boolean validCaSignature = isAikCertificateTrusted(hostAikCert); // XXX TODO this check belongs in the trust policy rules
                                    if( !validCaSignature ) {
                                        throw new ASException(ErrorCode.AS_INVALID_AIK_CERTIFICATE, host.getHostName().toString());
                                    }
                                }
                        }

                        // retrieve the complete manifest for  the host, includes ALL pcr's and if there is module info available it is included also.
                        if (pcrManifest == null)
                            pcrManifest = agent.getPcrManifest();  // currently Vmware has pcr+module, but in 1.2 we are adding module attestation for Intel hosts too ;   citrix would be just pcr for now i guess
                        

                        // send the pcr manifest to a vendor-specific class in order to extract any host-specific information
                        // for vmware this is the "HostTpmCommandLineEventDetails" which is a host-specific value and must be
                        // saved into mw_host_specific _manifest  (using the MLE information obtained with getBiosAndVmm(host) above...)
//                        HostReport hostReport = new HostReport();
//                        hostReport.aik = null; // TODO should be what we get above if it's available
//                        hostReport.pcrManifest = pcrManifest;
//                        hostReport.tpmQuote = null;
//                        hostReport.variables = new HashMap<String,String>(); // for example if we know a UUID ... we would ADD IT HERE

//                        TrustPolicy hostSpecificTrustPolicy = hostTrustPolicyFactory.createHostSpecificTrustPolicy(hostReport, biosMleId, vmmMleId); // XXX TODO add the bios mle and vmm mle information to HostReport ?? only if they are needed by some policies...
                        
                        // Bug: 749: We need to handle the host specific modules only if the PCR 19 is selected for attestation
                        List<TblHostSpecificManifest>   tblHostSpecificManifests = null;
                        if(vmmMleId.getRequiredManifestList().contains(PcrIndex.PCR19.toString())) {
                            log.info("Host specific modules would be retrieved from the host that extends into PCR 19.");
                            // Added the Vendor parameter to the below function so that we can handle the host specific records differently for different types of hosts.
                            tblHostSpecificManifests = createHostSpecificManifestRecords(vmmMleId, pcrManifest, hostType);
                        } else {
                            log.info("Host specific modules will not be configured since PCR 19 is not selected for attestation");
                        }
                        
                        // now for vmware specifically,  we have to pass this along to the vmware-specific function because it knows which modules are host-specific (the commandline event)  and has to store those in mw_host_specific  ...
//                            pcrMap = getHostPcrManifest(tblHosts, host); // BUG #497 sending both the new TblHosts record and the TxtHost object just to get the TlsPolicy into the initial call so that with the trust_first_certificate policy we will obtain the host certificate now while adding it
                        

                        // for all hosts (used to be just vmware, but no reason right now to make it vmware-specific...), if pcr 22 happens to match our location database, populate the location field in the host record
                            tblHosts.setLocation( getLocation(pcrManifest) );
                        
                        
                        //Bug: 597, 594 & 583. Here we were trying to get the length of the TlsKeystore without checking if it is NULL or not. 
                        // If in case it is NULL, it would throw NullPointerException                        
                        log.debug("Saving Host in database with TlsPolicyName {} and TlsKeystoreLength {}", tblHosts.getTlsPolicyName(), tblHosts.getTlsKeystore() == null ? "null" : tblHosts.getTlsKeystore().length);

                        log.trace("HOST BO CALLING SAVEHOSTINDATABASE");
                        Map<String,String> attributes = agent.getHostAttributes();
                        tblHosts.setHardwareUuid(attributes.get("Host_UUID").toLowerCase().trim());
                        saveHostInDatabase(tblHosts, host, pcrManifest, tblHostSpecificManifests, biosMleId, vmmMleId, uuid);
                        
                        // Now that the host has been registered successfully, let us see if there is an asset tag certificated configured for the host
                        // to which the host has to be associated
                        associateAssetTagCertForHost(host, agent.getHostAttributes()); //attributes);

		} catch (ASException ase) {
            //System.err.println("JIM DEBUG"); 
            //ase.printStackTrace(System.err);

			throw ase;
		} 
//                catch(CryptographyException e) {
//                    throw new ASException(e,ErrorCode.AS_ENCRYPTION_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
//                } 
        catch (Exception e) {
            //System.err.println("JIM DEBUG");
            //e.printStackTrace(System.err);
			// throw new ASException(e);
                        // Bug: 1038 - prevent leaks in error messages to client
                        log.error("Error during registration of host.", e);
                        throw new ASException(ErrorCode.AS_REGISTER_HOST_ERROR, e.getClass().getSimpleName());

		}
		return new HostResponse(ErrorCode.OK);
	}


    /**
     * XXX TODO : THIS IS A DUPLICATE OF WHAT IS THERE IN MANAGEMENT SERVICE HOSTBO.JAVA. IF YOU MAKE ANY CHANGE, PLEASE
     * CHANGE IT IN THE OTHER LOCATION AS WELL.
     * 
     * @param hostAikCert
     * @return 
     */
    private boolean isAikCertificateTrusted(X509Certificate hostAikCert) {
        // XXX code in this first section is duplciated in the IntelHostTrustPolicyFactory ... maybe refactor to put it into a configuration method? it's just loading list of trusted privacy ca's from the configuration.
        log.debug("isAikCertificateTrusted {}", hostAikCert.getSubjectX500Principal().getName());
        // TODO read privacy ca certs from database and see if any one of them signed it. 
        // read privacy ca certificate.  if there is a privacy ca list file available (PrivacyCA.pem) we read the list from that. otherwise we just use the single certificate in PrivacyCA.cer (DER formatt)
        HashSet<X509Certificate> pcaList = new HashSet<X509Certificate>();
        try {
            InputStream privacyCaIn = new FileInputStream(ResourceFinder.getFile("PrivacyCA.list.pem")); // may contain multiple trusted privacy CA certs from remove Privacy CAs
            List<X509Certificate> privacyCaCerts = X509Util.decodePemCertificates(IOUtils.toString(privacyCaIn));
            pcaList.addAll(privacyCaCerts);
            IOUtils.closeQuietly(privacyCaIn);
            log.debug("Added {} certificates from PrivacyCA.list.pem", privacyCaCerts.size());
        }
        catch(Exception e) {
            // FileNotFoundException: cannot find PrivacyCA.pem
            // CertificateException: error while reading certificates from file
            log.warn("Cannot load PrivacyCA.list.pem");            
        }
        try {
            InputStream privacyCaIn = new FileInputStream(ResourceFinder.getFile("PrivacyCA.pem")); // may contain one trusted privacy CA cert from local Privacy CA
            X509Certificate privacyCaCert = X509Util.decodePemCertificate(IOUtils.toString(privacyCaIn));
            pcaList.add(privacyCaCert);
            IOUtils.closeQuietly(privacyCaIn);
            log.debug("Added certificate from PrivacyCA.pem");
        }
        catch(Exception e) {
            // FileNotFoundException: cannot find PrivacyCA.pem
            // CertificateException: error while reading certificate from file
            log.warn("Cannot load PrivacyCA.pem");            
        }
        // XXX code in this second section is also in  AikCertificateTrusted rule in trust-policy... we could just apply that rule directly here instead of duplicating the code.
        boolean validCaSignature = false;
        for(X509Certificate pca : pcaList) {
            try {
                if( Arrays.equals(pca.getSubjectX500Principal().getEncoded(), hostAikCert.getIssuerX500Principal().getEncoded()) ) {
                    log.debug("Found matching CA: {}", pca.getSubjectX500Principal().getName());
                    pca.checkValidity(hostAikCert.getNotBefore()); // Privacy CA certificate must have been valid when it signed the AIK certificate
                    hostAikCert.verify(pca.getPublicKey()); // verify the trusted privacy ca signed this aik cert.  throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
                    // TODO read the CRL for this privacy ca and ensure this AIK cert has not been revoked
                    // TODO check if the privacy ca cert is self-signed... if it's not self-signed  we should check for a path leading to a known root ca in the root ca's file
                    validCaSignature = true;
                }
            }
            catch(Exception e) {
                log.debug("Failed to verify AIK signature with CA", e); // but don't re-throw because maybe another cert in the list is a valid signer
            }
        }
        return validCaSignature;
    }

	private String getLocation(PcrManifest pcrManifest) throws IOException {
        if( pcrManifest == null ) { return null; }
        if( pcrManifest.containsPcr(LOCATION_PCR) ) {
            String value = pcrManifest.getPcr(LOCATION_PCR).getValue().toString();
            return My.jpa().mwLocationPcr().findTblLocationPcrByPcrValue(value);
        }
		return null;
    }
    
    private void createHostSpecificManifest(List<TblHostSpecificManifest> tblHostSpecificManifests, TblHosts tblHosts) throws IOException {
        if (tblHostSpecificManifests != null && !tblHostSpecificManifests.isEmpty()) {
            for(TblHostSpecificManifest tblHostSpecificManifest : tblHostSpecificManifests){
                    tblHostSpecificManifest.setHostID(tblHosts.getId());
                    My.jpa().mwHostSpecificManifest().create(tblHostSpecificManifest);
            }
        }
    }


        public HostResponse updateHost(TxtHost host, PcrManifest pcrManifest, HostAgent agent, String uuid) {
                List<TblHostSpecificManifest> tblHostSpecificManifests = null;
                Vendor hostType;
                try {
                        TblHosts tblHosts = null;
                        if (uuid != null && !uuid.isEmpty()) {
                            tblHosts = My.jpa().mwHosts().findHostByUuid(uuid);
                        } else {                            
                            tblHosts = getHostByName(host.getHostName()); // datatype.Hostname
                        }
                        if (tblHosts == null) {
                                throw new ASException(ErrorCode.AS_HOST_NOT_FOUND, host.getHostName().toString());
                        }

          TblMle  biosMleId = findBiosMleForHost(host); 
          TblMle  vmmMleId = findVmmMleForHost(host); 
            

                        // need to update with the new connection string before we attempt to connect to get any updated info from host (aik cert, manifest, etc)
                        if (tblHosts.getTlsPolicyName() == null && tblHosts.getTlsPolicyName().isEmpty()) { // XXX new code to test
                                tblHosts.setTlsPolicyName(My.configuration().getDefaultTlsPolicyName()); // XXX  bug #497  the TxtHost object doesn't have the ssl certificate and policy
                        }
//                        tblHosts.setTlsKeystore(null);  // XXX new code to test: it's either null or it's already set so don't change it // XXX  bug #497  the TxtHost object doesn't have the ssl certificate and policy 
                        tblHosts.setAddOnConnectionInfo(host.getAddOn_Connection_String());
                        
                        // Using the connection string we will find out the type of the host. This information would be used later
                        ConnectionString hostConnString = new ConnectionString(host.getAddOn_Connection_String());
                        tblHosts.setAddOnConnectionInfo(hostConnString.getConnectionStringWithPrefix());
                        hostType = hostConnString.getVendor();
                        
                        if (host.getHostName() != null) {
                                tblHosts.setName(host.getHostName().toString());
                        }
                        if (host.getHostName() != null) {
                                tblHosts.setIPAddress(host.getHostName().toString());
                        }
                        if (host.getPort() != null) {
                                tblHosts.setPort(host.getPort());
                        }

                        if (agent == null) {
                            HostAgentFactory factory = new HostAgentFactory();
                            agent = factory.getHostAgent(tblHosts);
                        }
                        
                        if( agent.isAikAvailable() ) {
                            log.debug("Getting identity.");
                                setAikForHost(tblHosts, host, agent);
                        }
                        
                            if(vmmMleId.getId().intValue() != tblHosts.getVmmMleId().getId().intValue() ){
                                log.info("VMM is updated. Update the host specific manifest");
                                // retrieve the complete manifest for  the host, includes ALL pcr's and if there is module info available it is included also.
                                if (pcrManifest == null)
                                    pcrManifest = agent.getPcrManifest();  // currently Vmware has pcr+module, but in 1.2 we are adding module attestation for Intel hosts too ;   citrix would be just pcr for now i guess


                                // send the pcr manifest to a vendor-specific class in order to extract any host-specific information
                                // for vmware this is the "HostTpmCommandLineEventDetails" which is a host-specific value and must be
                                // saved into mw_host_specific _manifest  (using the MLE information obtained with getBiosAndVmm(host) above...)
//                                HostReport hostReport = new HostReport();
//                                hostReport.aik = null; // TODO should be what we get above if it's available
//                                hostReport.pcrManifest = pcrManifest;
//                                hostReport.tpmQuote = null;
//                                hostReport.variables = new HashMap<String,String>(); // for example if we know a UUID ... we would ADD IT HERE
//                                TrustPolicy hostSpecificTrustPolicy = hostTrustPolicyFactory.createHostSpecificTrustPolicy(hostReport, biosMleId, vmmMleId); // XXX TODO add the bios mle and vmm mle information to HostReport ?? only if they are needed by some policies...
                                
                                // Bug 962: Earlier we were trying to delete the old host specific values after the host update. By then the VMM MLE would
                                // already be updated and the query would not find any values to delete.
                                deleteHostSpecificManifest(tblHosts);
                                
                                // Bug 963: We need to check if the white list configured for the MLE requires PCR 19. If not, we will skip creating
                                // the host specific modules.
                                if(vmmMleId.getRequiredManifestList().contains(PcrIndex.PCR19.toString())) {
                                    log.debug("Host specific modules would be retrieved from the host that extends into PCR 19.");
                                    // Added the Vendor parameter to the below function so that we can handle the host specific records differently for different types of hosts.
                                    tblHostSpecificManifests = createHostSpecificManifestRecords(vmmMleId, pcrManifest, hostType);
                                } else {
                                    log.debug("Host specific modules will not be configured since PCR 19 is not selected for attestation");
                                }
                            }

                        log.debug("Saving Host in database");
                        tblHosts.setBiosMleId(biosMleId);
                        // @since 1.1 we are relying on the audit log for "created on", "created by", etc. type information
                        // tblHosts.setUpdatedOn(new Date(System.currentTimeMillis()));
                        tblHosts.setDescription(host.getDescription());
                        tblHosts.setEmail(host.getEmail());
                        if (host.getHostName() != null) {
                                tblHosts.setIPAddress(host.getHostName().toString()); // datatype.IPAddress
                        }
                        if( host.getPort() != null ) { tblHosts.setPort(host.getPort()); }                        
                        tblHosts.setVmmMleId(vmmMleId);
                        tblHosts.setBios_mle_uuid_hex(biosMleId.getUuid_hex());
                        tblHosts.setVmm_mle_uuid_hex(vmmMleId.getUuid_hex());

			My.jpa().mwHosts().edit(tblHosts);
			log.info("Updated host: {}", tblHosts.getName());
                        
                        if(tblHostSpecificManifests != null){
                            log.debug("Updating Host Specific Manifest in database");
                            // Bug 962: Making this call earlier in the function before updating the host with the new MLEs.
                            //deleteHostSpecificManifest(tblHosts);
                            createHostSpecificManifest(tblHostSpecificManifests, tblHosts);
                        }

                } catch (ASException ase) {
                        throw ase;
                } catch (CryptographyException e) {
                        throw new ASException(e, ErrorCode.AS_ENCRYPTION_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
                } catch (Exception e) {
                        // throw new ASException(e);
                        // Bug: 1038 - prevent leaks in error messages to client
                        log.error("Error during host update.", e);
                        throw new ASException(ErrorCode.AS_UPDATE_HOST_ERROR, e.getClass().getSimpleName());                        
                }

                return new HostResponse(ErrorCode.OK);
        }

        public HostResponse deleteHost(Hostname hostName, String uuid) { // datatype.Hostname

                try {
                        TblHosts tblHosts = null;
                        if (uuid != null && !uuid.isEmpty()) {
                            tblHosts = My.jpa().mwHosts().findHostByUuid(uuid);
                            hostName = new Hostname(tblHosts.getName());
                        } else {                            
                            tblHosts = getHostByName(hostName);
                        }
                        
                        if (tblHosts == null) {
                                throw new ASException(ErrorCode.AS_HOST_NOT_FOUND, hostName);
                        }
                        log.debug("Deleting Host from database");
                        
                        deleteHostAssetTagMapping(tblHosts);
                        
                        deleteHostSpecificManifest(tblHosts);

                        deleteTALogs(tblHosts.getId());

                        deleteSAMLAssertions(tblHosts);

                        My.jpa().mwHosts().destroy(tblHosts.getId());
                        log.info("Deleted host: {}", hostName.toString());
                        
                        // Now that the host is deleted, we need to remove any asset tag certificate mapped to this host
                        unmapAssetTagCertFromHost(tblHosts.getId(), tblHosts.getName());
                        
                } catch (ASException ase) {
                        //System.err.println("JIM DEBUG"); 
                        //ase.printStackTrace(System.err);
                        throw ase;
                } catch (CryptographyException e) {
                        //System.err.println("JIM DEBUG"); 
                        //e.printStackTrace(System.err);
                        throw new ASException(ErrorCode.SYSTEM_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage(), e);
                        //throw new ASException(ErrorCode.SYSTEM_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage(), e);
                } catch (Exception e) {
                        //System.err.println("JIM DEBUG"); 
                        //e.printStackTrace(System.err);
                        // throw new ASException(e);
                        // Bug: 1038 - prevent leaks in error messages to client
                        log.error("Error during host deletion.", e);
                        throw new ASException(ErrorCode.AS_DELETE_HOST_ERROR, e.getClass().getSimpleName());                        
                }
                return new HostResponse(ErrorCode.OK);
        }
        
        private void deleteHostAssetTagMapping(TblHosts tblHosts) throws NonexistentEntityException, IOException {
            AssetTagCertAssociateRequest atagRequest = new AssetTagCertAssociateRequest();
            atagRequest.setHostID(tblHosts.getId());
            AssetTagCertBO atagBO = new AssetTagCertBO();
            atagBO.unmapAssetTagCertFromHostById(atagRequest);            
        }
        
        // PREMIUM FEATURE ? 
        private void deleteHostSpecificManifest(TblHosts tblHosts)
                throws NonexistentEntityException, IOException {
                TblHostSpecificManifestJpaController tblHostSpecificManifestJpaController = My.jpa().mwHostSpecificManifest();
                
                for(TblModuleManifest moduleManifest : tblHosts.getVmmMleId().getTblModuleManifestCollection()) {
                     if( moduleManifest.getUseHostSpecificDigestValue() != null && moduleManifest.getUseHostSpecificDigestValue().booleanValue() ) {
                        // For open source we used to have multiple module manifests for the same hosts. So, the below query by hostID was returning multiple results.
                        //String hostSpecificDigestValue = new TblHostSpecificManifestJpaController(getEntityManagerFactory()).findByHostID(hostId).getDigestValue();
                        TblHostSpecificManifest hostSpecificManifest = tblHostSpecificManifestJpaController.findByModuleAndHostID(tblHosts.getId(), moduleManifest.getId());
                        if (hostSpecificManifest != null) {
                                log.debug("Deleting Host specific manifest." + moduleManifest.getComponentName() + ":" + hostSpecificManifest.getDigestValue());
                                tblHostSpecificManifestJpaController.destroy(hostSpecificManifest.getId());
                        }                        
                    }
                }                
        }

        private void deleteTALogs(Integer hostId) throws IllegalOrphanException, IOException {

                TblTaLogJpaController tblTaLogJpaController = My.jpa().mwTaLog(); // new TblTaLogJpaController(getEntityManagerFactory());

                List<TblTaLog> taLogs = tblTaLogJpaController.findLogsByHostId(hostId, new Date());

                if (taLogs != null) {

                        for (TblTaLog taLog : taLogs) {
                                try {
                                        tblTaLogJpaController.destroy(taLog.getId());
                                } catch (NonexistentEntityException e) {
                                        log.error("Ta Log is already deleted " + taLog.getId());
                                }
                        }
                        log.info("Deleted all the logs for the given host " + hostId);
                }

        }

        /**
         * Deletes all the SAML assertions for the specified host. This should
         * be called before deleting the host.
         *
         * @param hostId
         */
        private void deleteSAMLAssertions(TblHosts hostId) throws IOException {
                TblSamlAssertionJpaController samlJpaController = My.jpa().mwSamlAssertion(); //new TblSamlAssertionJpaController(getEntityManagerFactory());

                List<TblSamlAssertion> hostSAMLAssertions = samlJpaController.findByHostID(hostId);

                if (hostSAMLAssertions != null) {
                        for (TblSamlAssertion hostSAML : hostSAMLAssertions) {
                                try {
                                        samlJpaController.destroy(hostSAML.getId());
                                } catch (NonexistentEntityException e) {
                                        log.error("Ta Log is already deleted " + hostSAML.getId());
                                }
                        }
                        log.info("Deleted all the logs for the given host " + hostId);
                }
        }

	private void setAikForHost(TblHosts tblHosts, TxtHost host, HostAgent agent) {
            //HostAgentFactory factory = new HostAgentFactory(); // we could call IntelHostAgentFactory but then we have to create the TlsPolicy object ourselves... the HostAgentFactory does that for us.
            //HostAgent agent = factory.getHostAgent(tblHosts);
            if( agent.isAikAvailable() ) {
                if( agent.isAikCaAvailable() ) {
                    X509Certificate cert = agent.getAikCertificate();
                    try {
                        String certPem = X509Util.encodePemCertificate(cert);
                        tblHosts.setAIKCertificate(certPem);
                        tblHosts.setAikPublicKey(RsaUtil.encodePemPublicKey(cert.getPublicKey())); // NOTE: we are getting the public key from the cert, NOT by calling agent.getAik() ... that's to ensure that someone doesn't give us a valid certificate and then some OTHER public key that is not bound to the TPM
                        tblHosts.setAikSha1(Sha1Digest.valueOf(cert.getEncoded()).toString());
                        tblHosts.setAikPublicKeySha1(Sha1Digest.valueOf(cert.getPublicKey().getEncoded()).toString());
                    }
                    catch(Exception e) {
                        log.error("Cannot encode AIK certificate: "+e.toString(), e);
                    }
                }
                else {
                    PublicKey publicKey = agent.getAik();
                    String pem = RsaUtil.encodePemPublicKey(publicKey); 
                    tblHosts.setAIKCertificate(null);
                    tblHosts.setAikPublicKey(pem);
                    tblHosts.setAikSha1(null);
                    tblHosts.setAikPublicKeySha1(Sha1Digest.valueOf(publicKey.getEncoded()).toString());
                }
            }
 	}

        /**
         *
         * @param host must not be null
         */
//	private void validate(TxtHost host) {
//		HashSet<String> missing = new HashSet<String>();
        // phase 1, check for required fields
		/*
         * if( host.getHostName() == null || host.getHostName().isEmpty() ) {
         * missing.add("HostName"); } if( host.getBIOS_Name() == null ||
         * host.getBIOS_Name().isEmpty() ) { missing.add("BIOS_Name"); } if(
         * host.getVMM_Name() == null || host.getVMM_Name().isEmpty() ) {
         * missing.add("VMM_Name"); } if( !missing.isEmpty() ) { throw new
         * ASException(ErrorCode.VALIDATION_ERROR,
         * "Missing "+TextUtil.join(missing)); }
         */
        // phase 2, check for conditionally required fields
        // String errorMessage = "";
        // If in case we are adding a ESX host we need to ensure that we are
        // getting the connection string
        // for the vCenter server as well.
//		log.info( "VMM Name {}", host.getVmm());

        /*
         * if (requiresConnectionString(host.getVmm().getName())) {
         * if(host.getAddOn_Connection_String() == null ||
         * host.getAddOn_Connection_String().isEmpty()) { missing.add(
         * "AddOn connection string for connecting to vCenter server for host: "
         * +host.getHostName()); } } else { if( host.getIPAddress() == null ||
         * host.getIPAddress().isEmpty() ) { missing.add("IPAddress"); } if(
         * host.getPort() == null ) { missing.add("Port"); } }
         */
//		if (!missing.isEmpty()) {
//			throw new ASException(ErrorCode.VALIDATION_ERROR, "Missing "
//					+ TextUtil.join(missing));
//		}
//	}

        /*
         * private boolean requiresConnectionString(String vmmName) { if(
         * hostname.contains("ESX") ) { return true; } return false; }
         */
        private void getBiosAndVMM(TxtHost host) throws IOException {
                TblMleJpaController mleController = My.jpa().mwMle(); //new TblMleJpaController(getEntityManagerFactory());
                this.biosMleId = mleController.findBiosMle(host.getBios().getName(),
                        host.getBios().getVersion(), host.getBios().getOem());
                if (biosMleId == null) {
                        throw new ASException(ErrorCode.AS_BIOS_INCORRECT, host.getBios().getName(), host.getBios().getVersion());
                }
                this.vmmMleId = mleController.findVmmMle(host.getVmm().getName(), host
                        .getVmm().getVersion(), host.getVmm().getOsName(), host
                        .getVmm().getOsVersion());
                if (vmmMleId == null) {
                        throw new ASException(ErrorCode.AS_VMM_INCORRECT, host.getVmm().getName(), host.getVmm().getVersion());
                }
        }

	private TblMle findBiosMleForHost(TxtHost host) throws IOException {
		
		TblMle biosMleId = My.jpa().mwMle().findBiosMle(host.getBios().getName(),
				host.getBios().getVersion(), host.getBios().getOem());
		if (biosMleId == null) {
			throw new ASException(ErrorCode.AS_BIOS_INCORRECT, host.getBios().getName(),host.getBios().getVersion());
		}
        return biosMleId;
	}
	private TblMle findVmmMleForHost(TxtHost host) throws IOException {
		TblMle vmmMleId = My.jpa().mwMle().findVmmMle(host.getVmm().getName(), host
				.getVmm().getVersion(), host.getVmm().getOsName(), host
				.getVmm().getOsVersion());
		if (vmmMleId == null) {
			throw new ASException(ErrorCode.AS_VMM_INCORRECT, host.getVmm().getName(),host.getVmm().getVersion());
		}
        return vmmMleId;
	}

    // BUG #607 changing HashMap<String, ? extends IManifest> pcrMap to PcrManifest
	private synchronized void saveHostInDatabase(TblHosts newRecordWithTlsPolicyAndKeystore, TxtHost host, PcrManifest pcrManifest, List<TblHostSpecificManifest> tblHostSpecificManifests, TblMle biosMleId, TblMle vmmMleId, String uuid) throws CryptographyException, MalformedURLException, IOException {
		checkForDuplicate(host);
		TblHosts tblHosts = newRecordWithTlsPolicyAndKeystore; // new TblHosts();       
		log.debug("Saving Host in database with TlsPolicyName {} and TlsKeystoreLength {}", tblHosts.getTlsPolicyName(), (tblHosts.getTlsKeystore() == null ? "null" : tblHosts.getTlsKeystore().length));
		
		String cs = host.getAddOn_Connection_String();
                //log.info("saveHostInDatabase cs = " + cs);
		tblHosts.setAddOnConnectionInfo(cs);
		tblHosts.setBiosMleId(biosMleId);
                // @since 1.1 we are relying on the audit log for "created on", "created by", etc. type information
                // tblHosts.setCreatedOn(new Date(System.currentTimeMillis()));
                // tblHosts.setUpdatedOn(new Date(System.currentTimeMillis()));
                tblHosts.setDescription(host.getDescription());
                tblHosts.setEmail(host.getEmail());
                if (host.getHostName() != null) {
                        tblHosts.setIPAddress(host.getHostName().toString()); // datatype.IPAddress
                }else{
                        tblHosts.setIPAddress(host.getHostName().toString());
                }
                tblHosts.setName(host.getHostName().toString()); // datatype.Hostname

                if (host.getPort() != null) {
                        tblHosts.setPort(host.getPort());
                }
                tblHosts.setVmmMleId(vmmMleId);
                
                // We need to check if the user has passed in the UUID or we need to generate one
                if (uuid != null && !uuid.isEmpty())
                    tblHosts.setUuid_hex(uuid);
                else
                    tblHosts.setUuid_hex(new UUID().toString());
                tblHosts.setBios_mle_uuid_hex(biosMleId.getUuid_hex());
                tblHosts.setVmm_mle_uuid_hex(vmmMleId.getUuid_hex());
                
                // Bug:583: Since we have seen exception related to this in the log file, we will check for contents
                // before setting the location value.
//                if (location != null) {
//                    tblHosts.setLocation(location);
//                }
                // create the host
                log.trace("COMMITING NEW HOST DO DATABASE");
                //log.error("saveHostInDatabase tblHost  aik=" + tblHosts.getAIKCertificate() + ", cs=" + tblHosts.getAddOnConnectionInfo() + ", aikPub=" + tblHosts.getAikPublicKey() + 
                //          ", aikSha=" + tblHosts.getAikSha1() + ", desc=" + tblHosts.getDescription() + ", email=" + tblHosts.getEmail() + ", error=" + tblHosts.getErrorDescription() + ", ip=" +
                //          tblHosts.getIPAddress() + ", loc=" + tblHosts.getLocation() + ", name=" + tblHosts.getName() + ", tls=" + tblHosts.getTlsPolicyName() + ", port=" + tblHosts.getPort());
                try {
                    My.jpa().mwHosts().create(tblHosts);
                }catch (Exception e){
                    log.debug("SaveHostInDatabase caught ex!");
                    e.printStackTrace();
                    log.trace("end print stack trace");
                    // throw new ASException(e);
                    // Bug: 1038 - prevent leaks in error messages to client
                    log.error("Error during saving the host to DB.", e);
                    throw new ASException(ErrorCode.AS_REGISTER_HOST_ERROR, e.getClass().getSimpleName());
                }
                log.debug("Save host specific manifest if any.");
                createHostSpecificManifest(tblHostSpecificManifests, tblHosts);
        }

    /*
     * It looks for a very specific event that
     * is extended into pcr 19 in vmware hosts.  So the vmware host-specific policy factory creates a TrustPolicy
     * that has that event,  and here we just convert it to a TblHostSpecificManifest record.
     * BUG #607 ... given a complete list of pcrs and module values from the host, and list of pcr's that should be used ... figures out 
     * what host-specific module values should be recorded in the database... apparently hard-coded to pcr 19
     * and vmware information... so this is a candidate for moving into VmwareHostTrustPolicyFactory,
     * and instaed of returning a "host-specific manifest" it should return a list of policies with module-included
     * or module-equals type rules.    XXX for now converting to PcrManifest but this probably still needs to be moved.
    */
    private List<TblHostSpecificManifest> createHostSpecificManifestRecords(TblMle vmmMleId, PcrManifest pcrManifest, Vendor hostType) throws IOException {
        List<TblHostSpecificManifest> tblHostSpecificManifests = new ArrayList<TblHostSpecificManifest>();

        // Using the connection string, let us first find out the host type
        // Bug 963: Ensure that we even check if PCR 19 is required as per the MLE setup
        if (vmmMleId.getRequiredManifestList().contains(PcrIndex.PCR19.toString()) && pcrManifest != null && pcrManifest.containsPcrEventLog(PcrIndex.PCR19)) {
            PcrEventLog pcrEventLog = pcrManifest.getPcrEventLog(19);

            for (Measurement m : pcrEventLog.getEventLog()) {

                log.debug("Checking host specific manifest for event '"   + m.getInfo().get("EventName") + 
                        "' field '" + m.getLabel() + "' component '" + m.getInfo().get("ComponentName") + "'");
                
                // we are looking for the "commandline" event specifically  (vmware)
                if (hostType.equals(Vendor.VMWARE) && m.getInfo().get("EventName") != null && m.getInfo().get("EventName").equals("Vim25Api.HostTpmCommandEventDetails")) {

                    log.debug("Adding host specific manifest for event '"   + m.getInfo().get("EventName") + 
                            "' field '" + m.getLabel() + "' component '" + m.getInfo().get("ComponentName") + "'");
                    log.debug("Querying manifest for event '"   + m.getInfo().get("EventName") + 
                            "' MLE_ID '" + vmmMleId.getId() + "' component '" + m.getInfo().get("ComponentName") + "'");
                    
                    TblModuleManifest tblModuleManifest = My.jpa().mwModuleManifest().findByMleNameEventName(vmmMleId.getId(),
                            m.getInfo().get("ComponentName"),  m.getInfo().get("EventName"));

                    TblHostSpecificManifest tblHostSpecificManifest = new TblHostSpecificManifest();
                    tblHostSpecificManifest.setDigestValue(m.getValue().toString());
                    //					tblHostSpecificManifest.setHostID(tblHosts.getId());
                    tblHostSpecificManifest.setModuleManifestID(tblModuleManifest);
                    tblHostSpecificManifests.add(tblHostSpecificManifest);
                } else if (hostType.equals(Vendor.INTEL) && m.getInfo().get("EventName") != null) {
                    
                    log.debug("Adding host specific manifest for event '"   + m.getInfo().get("EventName") + 
                            "' field '" + m.getLabel() + "' component '" + m.getInfo().get("ComponentName") + "'");
                    log.debug("Querying manifest for event '"   + m.getInfo().get("EventName") + 
                            "' MLE_ID '" + vmmMleId.getId() + "' component '" + m.getInfo().get("ComponentName") + "'");
                    
                    // For open source XEN and KVM both the modules that get extended to PCR 19 should be added into the host specific table
                    TblModuleManifest tblModuleManifest = My.jpa().mwModuleManifest().findByMleNameEventName(vmmMleId.getId(),
                            m.getInfo().get("ComponentName"),  m.getInfo().get("EventName"));

                    TblHostSpecificManifest tblHostSpecificManifest = new TblHostSpecificManifest();
                    tblHostSpecificManifest.setDigestValue(m.getValue().toString());
                    tblHostSpecificManifest.setModuleManifestID(tblModuleManifest);
                    tblHostSpecificManifests.add(tblHostSpecificManifest);                    
                }
            }

            return tblHostSpecificManifests;
            
        } else {
            log.warn("No PCR 19 found.SO not saving host specific manifest.");
            return tblHostSpecificManifests;
        }
    }

        public HostResponse isHostRegistered(String hostnameOrAddress) {
                try {
                        TblHostsJpaController tblHostsJpaController = My.jpa().mwHosts(); //new TblHostsJpaController(getEntityManagerFactory());
                        TblHosts tblHosts = tblHostsJpaController.findByName(hostnameOrAddress);
                        if (tblHosts != null) {
                                return new HostResponse(ErrorCode.OK); // host name exists in
                                // database
                        }
                        tblHosts = tblHostsJpaController.findByIPAddress(hostnameOrAddress);
                        if (tblHosts != null) {
                                return new HostResponse(ErrorCode.OK); // host IP address exists in
                                // database
                        }
                        return new HostResponse(ErrorCode.AS_HOST_NOT_FOUND);
                } catch (ASException e) {
                        throw e;
                } catch (Exception e) {
                        // throw new ASException(e);
                        // Bug: 1038 - prevent leaks in error messages to client
                        log.error("Error during verification of registered host.", e);
                        throw new ASException(ErrorCode.AS_VERIFY_HOST_ERROR, e.getClass().getSimpleName());
                }
        }

        private void checkForDuplicate(TxtHost host) throws CryptographyException, IOException {
                TblHostsJpaController tblHostsJpaController = My.jpa().mwHosts(); //new TblHostsJpaController(getEntityManagerFactory());
                TblHosts tblHosts = tblHostsJpaController.findByName(host.getHostName()
                        .toString()); // datatype.Hostname
                if (tblHosts != null) {
                        throw new ASException(
                                ErrorCode.AS_HOST_EXISTS,
                                host.getHostName());
                }

                // BUG #497  every host requires a connection string now, and will not have the "ip address" field anymore. 
                /*
                 if (!host.requiresConnectionString() && host.getIPAddress() != null ) {
                 tblHosts = tblHostsJpaController.findByIPAddress(host
                 .getIPAddress().toString()); // datatype.IPAddress

                 if (tblHosts != null) {
                 throw new ASException(
                 ErrorCode.AS_IPADDRESS_EXISTS,
                 host.getIPAddress());
                 }
                 }
                 */
        }

        /**
         * This is not a REST API method, it is public because it is used by
         * HostTrustBO.
         *
         * @param hostName
         * @return
         * @throws CryptographyException
         */
        public TblHosts getHostByName(Hostname hostName) throws CryptographyException, IOException { // datatype.Hostname
                TblHosts tblHosts = My.jpa().mwHosts().findByName(hostName.toString());
                return tblHosts;
        }
	public TblHosts getHostByAik(Sha1Digest aik) throws CryptographyException, IOException { // datatype.Hostname
		TblHosts tblHosts = My.jpa().mwHosts().findByAikSha1(aik.toString());
		return tblHosts;
	}

        /**
         * Author: Sudhir
         *
         * Searches for the hosts using the criteria specified.
         *
         * @param searchCriteria: If in case the user has not provided any
         * search criteria, then all the hosts would be returned back to the
         * caller
         * @param includeHardwareUuid: if this is set to true, it causes the resulting 
         * TxtHostRecord to include the hardware_uuid field from the tblHost
         * @return
         */
        public List<TxtHostRecord> queryForHosts(String searchCriteria,boolean includeHardwareUuid) {
                log.debug("queryForHost " + searchCriteria + " includeHardwareUuid[" + includeHardwareUuid +"]");
                try {
                        TblHostsJpaController tblHostsJpaController = My.jpa().mwHosts(); //new TblHostsJpaController(getEntityManagerFactory());
                        List<TxtHostRecord> txtHostList = new ArrayList<TxtHostRecord>();
                        List<TblHosts> tblHostList;


                        if (searchCriteria != null && !searchCriteria.isEmpty()) {
                                tblHostList = tblHostsJpaController.findHostsByNameSearchCriteria(searchCriteria);
                        } else {
                                tblHostList = tblHostsJpaController.findTblHostsEntities();
                        }

                        if (tblHostList != null) {

                                log.debug(String.format("Found [%d] host results for search criteria [%s]", tblHostList.size(), searchCriteria));

                                for (TblHosts tblHosts : tblHostList) {
                                        TxtHostRecord hostObj = createTxtHostFromDatabaseRecord(tblHosts,includeHardwareUuid);
                                        txtHostList.add(hostObj);
                                }
                        } else {
                                log.debug(String.format("Found no hosts for search criteria [%s]", searchCriteria));
                        }

                        return txtHostList;
                } catch (ASException e) {
                        throw e;
                } catch (Exception e) {
                        // throw new ASException(e);
                        // Bug: 1038 - prevent leaks in error messages to client
                        log.error("Error during querying for registered hosts.", e);
                        throw new ASException(ErrorCode.AS_QUERY_HOST_ERROR, e.getClass().getSimpleName());
                }

        }

        
        /**
         * Author: Sudhir
         *
         * Searches for the hosts using the criteria specified.
         *
         * @param searchCriteria: If in case the user has not provided any
         * search criteria, then all the hosts would be returned back to the
         * caller
         * @return
         */
        public List<TxtHostRecord> queryForHosts(String searchCriteria) {
                log.debug("queryForHost " + searchCriteria);
                try {
                        TblHostsJpaController tblHostsJpaController = My.jpa().mwHosts(); //new TblHostsJpaController(getEntityManagerFactory());
                        List<TxtHostRecord> txtHostList = new ArrayList<TxtHostRecord>();
                        List<TblHosts> tblHostList;


                        if (searchCriteria != null && !searchCriteria.isEmpty()) {
                                tblHostList = tblHostsJpaController.findHostsByNameSearchCriteria(searchCriteria);
                        } else {
                                tblHostList = tblHostsJpaController.findTblHostsEntities();
                        }

                        if (tblHostList != null) {

                                log.debug(String.format("Found [%d] host results for search criteria [%s]", tblHostList.size(), searchCriteria));

                                for (TblHosts tblHosts : tblHostList) {
                                        TxtHostRecord hostObj = createTxtHostFromDatabaseRecord(tblHosts, false);
                                        txtHostList.add(hostObj);
                                }
                        } else {
                                log.debug(String.format("Found no hosts for search criteria [%s]", searchCriteria));
                        }

                        return txtHostList;
                } catch (ASException e) {
                        throw e;
                } catch (Exception e) {
                        // throw new ASException(e);
                        // Bug: 1038 - prevent leaks in error messages to client
                        log.error("Error during querying for registered hosts.", e);
                        throw new ASException(ErrorCode.AS_QUERY_HOST_ERROR, e.getClass().getSimpleName());
                }

        }

        public TxtHostRecord createTxtHostFromDatabaseRecord(TblHosts tblHost,boolean includeHardwareUuid) {
                TxtHostRecord hostObj = new TxtHostRecord();
                hostObj.HostName = tblHost.getName();
                hostObj.IPAddress = tblHost.getName();
                hostObj.Port = tblHost.getPort();
                hostObj.AddOn_Connection_String = tblHost.getAddOnConnectionInfo();
                hostObj.Description = tblHost.getDescription();
                hostObj.Email = tblHost.getEmail();
                hostObj.Location = tblHost.getLocation();
                hostObj.BIOS_Name = tblHost.getBiosMleId().getName();
                hostObj.BIOS_Oem = tblHost.getBiosMleId().getOemId().getName();
                hostObj.BIOS_Version = tblHost.getBiosMleId().getVersion();
                hostObj.VMM_Name = tblHost.getVmmMleId().getName();
                hostObj.VMM_Version = tblHost.getVmmMleId().getVersion();
                hostObj.VMM_OSName = tblHost.getVmmMleId().getOsId().getName();
                hostObj.VMM_OSVersion = tblHost.getVmmMleId().getOsId().getVersion();
                if(includeHardwareUuid){
                    log.debug("adding in hardware uuid field["+tblHost.getHardwareUuid()+"]");
                    hostObj.Hardware_Uuid = tblHost.getHardwareUuid();
                }else{
                    log.debug("not adding in hardware uuid");
                    hostObj.Hardware_Uuid = null;
                }
                return hostObj;
        }

        public HostResponse addHostByFindingMLE(TxtHostRecord hostObj) {
            try {
                return ASComponentFactory.getHostTrustBO().getTrustStatusOfHostNotInDBAndRegister(hostObj);
            } catch (ASException ae){
                throw ae;
			}
		}

        public HostResponse updateHostByFindingMLE(TxtHostRecord hostObj) {
            try {
                return ASComponentFactory.getHostTrustBO().getTrustStatusOfHostNotInDBAndRegister(hostObj);
            } catch (ASException ae) {
                throw ae;
            }
        }
        
    /**
     * 
     * @param host 
     */
    private void associateAssetTagCertForHost(TxtHost host, Map<String, String> hostAttributes) {
        String hostUUID;
        
        try {
            log.debug("Starting the procedure to map the asset tag certificate for host {}.", host.getHostName().toString());
            
            // First let us find if the asset tag is configured for this host or not. This information
            // would be available in the mw_asset_tag_certificate table, where the host's UUID would be
            // present.
            if (hostAttributes != null && hostAttributes.containsKey("Host_UUID")) {
                hostUUID = hostAttributes.get("Host_UUID");
            } else {
                log.info("Since UUID for the host {} is not specified, asset tag would not be configured.", host.getHostName().toString());
                return;
            }
            
            // Now that we have a valid host UUID, let us search for an entry in the db.
            AssetTagCertBO atagCertBO = new AssetTagCertBO();
            MwAssetTagCertificate atagCert = atagCertBO.findValidAssetTagCertForHost(hostUUID);
            if (atagCert != null) {
                log.debug("Found a valid asset tag certificate for the host {} with UUID {}.", host.getHostName().toString(), hostUUID);
                // Now that there is a asset tag certificate for the host, let us retrieve the host ID and update
                // the asset tag certificate with that ID
                TblHosts tblHost = My.jpa().mwHosts().findByName(host.getHostName().toString());
                if (tblHost != null) {
                    AssetTagCertAssociateRequest atagMapRequest = new AssetTagCertAssociateRequest();
                    atagMapRequest.setSha1OfAssetCert(atagCert.getSHA1Hash());
                    atagMapRequest.setHostID(tblHost.getId());
                    
                    boolean mapAssetTagCertToHost = atagCertBO.mapAssetTagCertToHostById(atagMapRequest);
                    if (mapAssetTagCertToHost)
                        log.info("Successfully mapped the asset tag certificate with UUID {} to host {}", atagCert.getUuid(), tblHost.getName());
                    else
                        log.info("No valid asset tag certificate configured for the host {}.", tblHost.getName());
                }
            } else {
                log.info("No valid asset tag certificate configured for the host {}.", host.getHostName().toString());
            }
            
        } catch (Exception ex) {
            // Log the error and return back.
            log.info("Error during asset tag configuration for the host {}. Details: {}.", host.getHostName().toString(), ex.getMessage());
        }
        
    }

    /**
     * 
     * @param id
     * @param name 
     */
    private void unmapAssetTagCertFromHost(Integer id, String name) {
        try {
            log.debug("Starting the procedure to unmap the asset tag certificate from host {}.", name);
                        
            AssetTagCertBO atagCertBO = new AssetTagCertBO();
            AssetTagCertAssociateRequest atagUnmapRequest = new AssetTagCertAssociateRequest();
            atagUnmapRequest.setHostID(id);
                    
            boolean unmapAssetTagCertFromHost = atagCertBO.unmapAssetTagCertFromHostById(atagUnmapRequest);
            if (unmapAssetTagCertFromHost)
                log.info("Either the asset tag certificate was successfully unmapped from the host {} or there was not asset tag certificate associated.", name);
            else
                log.info("Either there were errors or no asset tag certificate was configured for the host {}.", name);
            
        } catch (Exception ex) {
            // Log the error and return back.
            log.info("Error during asset tag unmapping for the host {}. Details: {}.", name, ex.getMessage());
        }
    }
}
