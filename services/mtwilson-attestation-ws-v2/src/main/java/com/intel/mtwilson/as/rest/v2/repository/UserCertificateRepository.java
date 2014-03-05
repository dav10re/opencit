/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.as.rest.v2.repository;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.rfc822.Rfc822Date;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.My;
import com.intel.mtwilson.as.rest.v2.model.UserCertificate;
import com.intel.mtwilson.as.rest.v2.model.UserCertificateCollection;
import com.intel.mtwilson.as.rest.v2.model.UserCertificateFilterCriteria;
import com.intel.mtwilson.as.rest.v2.model.UserCertificateLocator;
import com.intel.mtwilson.datatypes.ApiClientCreateRequest;
import com.intel.mtwilson.datatypes.ApiClientStatus;
import com.intel.mtwilson.datatypes.ApiClientUpdateRequest;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.jersey.resource.SimpleRepository;
import com.intel.mtwilson.ms.controller.ApiClientX509JpaController;
import com.intel.mtwilson.ms.data.ApiClientX509;
import com.intel.mtwilson.ms.data.ApiRoleX509;
import com.intel.mtwilson.ms.business.ApiClientBO;
import com.intel.mtwilson.ms.common.MSException;
import com.intel.mtwilson.ms.data.MwPortalUser;
import java.util.Date;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ssbangal
 */
public class UserCertificateRepository implements SimpleRepository<UserCertificate, UserCertificateCollection, UserCertificateFilterCriteria, UserCertificateLocator> {

    private Logger log = LoggerFactory.getLogger(getClass().getName());
        
    @Override
    public UserCertificateCollection search(UserCertificateFilterCriteria criteria) {
        UserCertificateCollection objCollection = new UserCertificateCollection();
        try {
            ApiClientX509JpaController userCertJpaController = My.jpa().mwApiClientX509();
            if (criteria.userUuid != null) {
                List<ApiClientX509> objList = userCertJpaController.findApiClientX509ByUserUUID(criteria.userUuid.toString());
                if (objList != null && !objList.isEmpty()) {
                    if (criteria.id != null) {
                        for(ApiClientX509 obj : objList) {
                            if (obj.getUuid_hex().equalsIgnoreCase(criteria.id.toString()))
                                objCollection.getUserCertificates().add(convert(obj));
                        }                        
                    } else if (criteria.nameEqualTo != null && !criteria.nameEqualTo.isEmpty()) {
                        for(ApiClientX509 obj : objList) {
                            if (obj.getName().equalsIgnoreCase(criteria.nameEqualTo.toString()))
                                objCollection.getUserCertificates().add(convert(obj));
                        }                        
                    } else if (criteria.nameContains != null && !criteria.nameContains.isEmpty()) {
                        for(ApiClientX509 obj : objList) {
                            if (obj.getName().contains(criteria.nameContains.toString()))
                                objCollection.getUserCertificates().add(convert(obj));
                        }                        
                    } else if (criteria.fingerprint != null) {
                        for(ApiClientX509 obj : objList) {
                            if (obj.getFingerprint().equals(criteria.fingerprint))
                                objCollection.getUserCertificates().add(convert(obj));
                        }                        
                    } else if (criteria.expiresAfter != null) {
                        for(ApiClientX509 obj : objList) {
                            if (obj.getExpires().after(criteria.expiresAfter))
                                objCollection.getUserCertificates().add(convert(obj));
                        }                        
                    } else if (criteria.expiresBefore != null) {
                        for(ApiClientX509 obj : objList) {
                            if (obj.getExpires().before(criteria.expiresBefore))
                                objCollection.getUserCertificates().add(convert(obj));
                        }                        
                    } else if (criteria.enabled != null) {
                        for(ApiClientX509 obj : objList) {
                            if (obj.getEnabled() == criteria.enabled)
                                objCollection.getUserCertificates().add(convert(obj));
                        }                        
                    } else if (criteria.status != null) {
                        for(ApiClientX509 obj : objList) {
                            if (obj.getStatus().equals(criteria.status))
                                objCollection.getUserCertificates().add(convert(obj));
                        }                        
                    } else {
                        for(ApiClientX509 obj : objList) {
                            objCollection.getUserCertificates().add(convert(obj));
                        }
                    }
                }                
            }             
        } catch (ASException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during user certificate search.", ex);
            throw new ASException(ErrorCode.MS_API_USER_SEARCH_ERROR, ex.getClass().getSimpleName());
        }
        return objCollection;
    }

    @Override
    public UserCertificate retrieve(UserCertificateLocator locator) {
        if (locator == null || locator.id == null) { return null; }        
        String id = locator.id.toString();
        try {
            ApiClientX509JpaController userCertJpaController = My.jpa().mwApiClientX509();
            ApiClientX509 user = userCertJpaController.findApiClientX509ByUUID(id);            
            if (user != null) {
                    UserCertificate userCert = convert(user);
                    return userCert;
            }
        } catch (ASException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during user certificate search.", ex);
            throw new ASException(ErrorCode.MS_API_USER_SEARCH_ERROR, ex.getClass().getSimpleName());
        }
        return null;
    }

    @Override
    public void store(UserCertificate item) {
        ApiClientUpdateRequest obj = new ApiClientUpdateRequest();
        try {
            obj.roles = item.getRoles();
            obj.comment = item.getComment();
            obj.enabled = item.isEnabled();
            obj.status = item.getStatus();
            new ApiClientBO().update(obj, item.getId().toString());
        } catch (MSException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during user certificate update.", ex);
            throw new ASException(ErrorCode.MS_API_USER_UPDATE_ERROR, ex.getClass().getSimpleName());
        }        
    }

    @Override
    public void create(UserCertificate item) {
        ApiClientCreateRequest obj = new ApiClientCreateRequest();
        try {
            // First make sure that the user is already configured in the user table
            MwPortalUser portalUser = My.jpa().mwPortalUser().findMwPortalUserByUUID(item.getUserUuid().toString());
            if (portalUser == null) {
                throw new ASException(ErrorCode.MS_USER_DOES_NOT_EXISTS, item.getUserUuid().toString());
            }
            
            obj.setCertificate(item.getCertificate());
            obj.setRoles(item.getRoles());
            new ApiClientBO().create(obj, item.getUserUuid().toString(), item.getId().toString());
        } catch (MSException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during user certificate creation.", ex);
            throw new ASException(ErrorCode.MS_API_USER_REGISTRATION_ERROR, ex.getClass().getSimpleName());
        }        
    }

    @Override
    public void delete(UserCertificateLocator locator) {
        if (locator == null || locator.id == null) { return; }
        String id = locator.id.toString();
        ApiClientUpdateRequest obj = new ApiClientUpdateRequest();
        try {
            obj.roles = new String[0];
            obj.comment = String.format("Deleted on %s", Rfc822Date.format(new Date()));
            obj.enabled = Boolean.FALSE;
            obj.status = ApiClientStatus.CANCELLED.toString();
            new ApiClientBO().update(obj, id);
        } catch (MSException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during user certificate update.", ex);
            throw new ASException(ErrorCode.MS_API_USER_UPDATE_ERROR, ex.getClass().getSimpleName());
        }        
    }

    @Override
    public void delete(UserCertificateFilterCriteria criteria) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    private UserCertificate convert(ApiClientX509 apiObj) {
        UserCertificate userCert = new UserCertificate();
        userCert.setId(UUID.valueOf(apiObj.getUuid_hex()));
        userCert.setName(apiObj.getName());
        userCert.setEnabled(apiObj.getEnabled());
        userCert.setCertificate(apiObj.getCertificate());
        userCert.setComment(apiObj.getComment());
        userCert.setExpires(apiObj.getExpires());
        userCert.setFingerprint(apiObj.getFingerprint());
        userCert.setIssuer(apiObj.getIssuer());
        userCert.setSerialNumber(apiObj.getSerialNumber());
        userCert.setStatus(apiObj.getStatus());
        String[] roles = new String[apiObj.getApiRoleX509Collection().size()];
        int i = 0;
        for(ApiRoleX509 role : apiObj.getApiRoleX509Collection()) {
            roles[i] = role.getApiRoleX509PK().getRole();
            i++;
        }
        userCert.setRoles(roles);
        return userCert;
    }

}