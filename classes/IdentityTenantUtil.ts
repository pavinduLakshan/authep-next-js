export class IdentityTenantUtil {
    static isTenantQualifiedUrlsEnabled(){
        return true;
    }

    static getTenantDomainFromContext(){
        return "tenantDomain"
    }
}