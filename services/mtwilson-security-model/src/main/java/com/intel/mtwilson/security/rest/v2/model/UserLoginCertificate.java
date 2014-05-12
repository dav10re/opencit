/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.security.rest.v2.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.intel.dcsg.cpg.x509.X509Util;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.jersey.CertificateDocument;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.Set;

/**
  id uuid DEFAULT NULL,
  user_id uuid DEFAULT NULL,
  certificate bytea NOT NULL,
  sha1_hash bytea NOT NULL,
  sha256_hash bytea NOT NULL,
  expires timestamp DEFAULT NULL,
  enabled boolean NOT NULL DEFAULT '0',
  status varchar(128) NOT NULL DEFAULT 'Pending',
  comment text,
 *
 * @author jbuhacoff
 */
@JacksonXmlRootElement(localName="user_login_certificate")
public class UserLoginCertificate extends CertificateDocument {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(UserLoginCertificate.class);
    
    private UUID id;
    private UUID userId;
    private byte[] certificate;
    private byte[] sha1Hash;
    private byte[] sha256Hash;
    private Date expires;
    private boolean enabled;
    private Status status;
    private String comment;
    private Set<String> roles;

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    public byte[] getSha1Hash() {
        return sha1Hash;
    }

    public void setSha1Hash(byte[] sha1Hash) {
        this.sha1Hash = sha1Hash;
    }

    public byte[] getSha256Hash() {
        return sha256Hash;
    }
    
    

    public void setSha256Hash(byte[] sha256Hash) {
        this.sha256Hash = sha256Hash;
    }

    

    
    public Date getExpires() {
        return expires;
    }

    public void setExpires(Date expires) {
        this.expires = expires;
    }
    
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
    
    
    @JsonIgnore
    @Override
    public X509Certificate getX509Certificate() {
        if( certificate == null ) { return null; }
        try {
            log.debug("Certificate bytes length {}", certificate.length);
            return X509Util.decodeDerCertificate(certificate);
        }
        catch(CertificateException ce) {
            //throw new IllegalArgumentException("Cannot decode certificate", e); // XXX TODO  for i18n we need to throw MWException here with an appropriate error code
            throw new ASException(ErrorCode.MS_CERTIFICATE_ENCODING_ERROR, ce.getClass().getSimpleName());
        }
    }

    @JsonIgnore
    @Override
    public void setX509Certificate(X509Certificate certificate) {
        if( certificate == null ) {
            this.certificate = null;
            return;
        }
        try {
            this.certificate = certificate.getEncoded();
            this.sha1Hash = Sha1Digest.digestOf(this.certificate).toByteArray();
            this.sha256Hash = Sha256Digest.digestOf(this.certificate).toByteArray();
        }
        catch(CertificateEncodingException ce) {
            log.error("Error decoding certificat.", ce);
            //throw new IllegalArgumentException("Cannot decode certificate", e); // XXX TODO  for i18n we need to throw MWException here with an appropriate error code
            throw new ASException(ErrorCode.MS_CERTIFICATE_ENCODING_ERROR, ce.getClass().getSimpleName());
        }
    }
    
    
}
