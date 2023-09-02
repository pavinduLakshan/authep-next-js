import { useEffect, useState } from "react";
import { IdentityTenantUtil } from "./classes/IdentityTenantUtil";
import config from './public/config.json'
import { useSearchParams } from 'next/navigation'

export function getInitParameter(key: string) {
    return config[key as keyof typeof config];
}

export const useInitUrl = () => {
    const searchParams = useSearchParams()

    const [samlssoURL,setSamlssoURL] = useState<string>("../samlsso");
    const [commonauthURL,setcommonauthURL] = useState<string>("../commonauth");
    const [oauth2AuthorizeURL,setOauth2AuthorizeURL] = useState<string>("../oauth2/authorize");
    const [oidcLogoutURL,setOidcLogoutURL] = useState<string>("../oidc/logout");
    const [openidServerURL,setOpenIDServerURL] = useState<string>("../openidserver");
    const [logincontextURL,setLogincontextURL] = useState<string>("../logincontext");   
    
    const [tenantDomain, setTenantDomain] = useState<string>("");
    const [userTenantDomain, setUserTenantDomain] = useState<string>("");

    useEffect(() => {
        // authenticationendpoint.identity_server_endpoint_url
        const identityServerEndpointContextParam: string = getInitParameter("IdentityServerEndpointContextURL") as string;

        if (identityServerEndpointContextParam) {
            setSamlssoURL(identityServerEndpointContextParam + "/samlsso");
            setcommonauthURL(identityServerEndpointContextParam + "/commonauth");
            setOauth2AuthorizeURL(identityServerEndpointContextParam + "/oauth2/authorize");
            setOidcLogoutURL(identityServerEndpointContextParam + "/oidc/logout");
            setOpenIDServerURL(identityServerEndpointContextParam + "/oidc/logout");
            setLogincontextURL(identityServerEndpointContextParam + "/logincontext");
        }
    },[])

    useEffect(() => {
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            setTenantDomain(IdentityTenantUtil.getTenantDomainFromContext());
            setUserTenantDomain(searchParams.get("ut") || searchParams.get("t") || tenantDomain);
        } else {
            setTenantDomain(searchParams.get("tenantDomain") || searchParams.get("t") || "");
            setUserTenantDomain(tenantDomain);
        }
    },[searchParams,tenantDomain])

    return {
        samlssoURL,
        commonauthURL,
        oauth2AuthorizeURL,
        oidcLogoutURL,
        openidServerURL,
        logincontextURL, 
        tenantDomain, 
        userTenantDomain
    }
}








