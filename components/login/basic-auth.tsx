import { FormEvent, useEffect, useState } from "react";
import { getInitParameter, useInitUrl } from "../../init-url";
import { useSearchParams } from "next/navigation";
import { IdentityCoreConstants } from "../../classes/IdentityCoreConstants";

const isBackChannelBasicAuth = false;

// <%@ page import="org.apache.cxf.jaxrs.client.JAXRSClientFactory" %>
// <%@ page import="org.apache.cxf.jaxrs.provider.json.JSONProvider" %>
// <%@ page import="org.apache.cxf.jaxrs.client.WebClient" %>
// <%@ page import="org.apache.http.HttpStatus" %>
// <%@ page import="org.owasp.encoder.Encode" %>
// <%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.client.SelfUserRegistrationResource" %>
// <%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.AuthenticationEndpointUtil" %>
// <%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.bean.ResendCodeRequestDTO" %>
// <%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.bean.PropertyDTO" %>
// <%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.bean.UserDTO" %>
// <%@ page import="java.net.URLEncoder" %>
// <%@ page import="java.net.URLDecoder" %>
// <%@ page import="java.util.regex.Pattern" %>
// <%@ page import="javax.ws.rs.core.Response" %>
// <%@ page import="javax.servlet.http.HttpServletRequest" %>
// <%@ page import="static org.wso2.carbon.identity.core.util.IdentityUtil.isSelfSignUpEPAvailable" %>
// <%@ page import="static org.wso2.carbon.identity.core.util.IdentityUtil.isRecoveryEPAvailable" %>
// <%@ page import="static org.wso2.carbon.identity.core.util.IdentityUtil.isEmailUsernameEnabled" %>
// <%@ page import="static org.wso2.carbon.identity.core.util.IdentityUtil.getServerURL" %>
// <%@ page import="org.apache.commons.codec.binary.Base64" %>
// <%@ page import="org.apache.commons.text.StringEscapeUtils" %>
// <%@ page import="java.nio.charset.Charset" %>
// <%@ page import="org.wso2.carbon.base.ServerConfiguration" %>
// <%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.EndpointConfigManager" %>
// <%@ page import="org.wso2.carbon.identity.core.URLBuilderException" %>
// <%@ page import="org.wso2.carbon.identity.core.ServiceURLBuilder" %>
// <%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.IdentityManagementEndpointUtil" %>
// <%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.ApplicationDataRetrievalClient" %>
// <%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.ApplicationDataRetrievalClientException" %>
// <%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.PreferenceRetrievalClient" %>
// <%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.PreferenceRetrievalClientException" %>

const commonauthURL = "https://localhost:9443/commonauth";

// <jsp:directive.include file="includes/init-loginform-action-url.jsp"/>
// <jsp:directive.include file="plugins/basicauth-extensions.jsp"/>

export const BasicAuth = () => {

    const searchParams = useSearchParams();

    const { samlssoURL, oauth2AuthorizeURL } = useInitUrl();

    const [proxyContextPath,setProxyContextPath] = useState<string>("")
    const [username,setUsername] = useState<string>("")
    const [password,setPassword] = useState<string>("")
    const [loginFailed,setLoginFailed] = useState<boolean>(false);
    const [reCaptchaEnabled,setReCaptchaEnabled] = useState<boolean>(false);
    const [reCaptchaResendEnabled,setReCaptchaResendEnabled] = useState<boolean>(false);

    const isRecoveryEPAvailable = getInitParameter("EnableRecoveryEndpoint");
    const isSelfSignUpEPAvailable = getInitParameter("EnableSelfSignUpEndpoint");

    // TODO: update using the values from data retrieval client
    const [identityMgtEndpointContext,setIdentityMgtEndpointContext] = useState<string>("");
    const [accountRegistrationEndpointURL,setAccountRegistrationEndpointURL] = useState<string>("");
    const [urlEncodedURL,setUrlEncodedURL] = useState<string>("");
    const [urlParameters,setUrlParameters] = useState<string>("");

    // TODO: should be updated with configs retrieved from the preference retrieval client
    const [isUsernameRecoveryEnabledInTenant,setIsUsernameRecoveryEnabledInTenant] = useState<boolean>(true);
    const [isPasswordRecoveryEnabledInTenant,setIsPasswordRecoveryEnabledInTenant] = useState<boolean>(true);
    const [isSelfSignUpEnabledInTenant,setIsSelfSignUpEnabledInTenant] = useState<boolean>(true);

    const [errorCode,setErrorCode] = useState<string>("")

    const [passwordInputType,setPasswordInputType] = useState<string>("password")

    const {logincontextURL} = useInitUrl();

    const getLoginFormActionUrl = () => {
        const queryString = global?.window && window.location.search;
        const urlParams = new URLSearchParams(queryString);

        let loginFormActionURL = "";
    
        if (isBackChannelBasicAuth) {
            loginFormActionURL = "authenticate.do";
            
            const queryString = global?.window && window.location.search;

            if (queryString != "" || queryString) {
                loginFormActionURL = loginFormActionURL + "?" + queryString?.substring(1);
            }
        } else {
            const type: string | null = urlParams.get("type");
            if (type === "samlsso") {
                loginFormActionURL = samlssoURL;
            } else {
                loginFormActionURL = commonauthURL;
            }
        }

        return loginFormActionURL;
    }

    const togglePasswordInputType = () => {
        if (passwordInputType === "password") {
            setPasswordInputType("text")
        } else if (passwordInputType === "password") {
            setPasswordInputType("password")
        }
    }

    useEffect(() => {
        if (searchParams.get("authFailure") === 'true') {
            setLoginFailed(true)
        }

        setErrorCode(searchParams.get("errorCode") || "")

        if (searchParams.get("reCaptcha") != null && searchParams.get("reCaptcha") === 'true') {
            setReCaptchaEnabled(true)
        }

        if (searchParams.get("reCaptchaResend") === "true") {
            setReCaptchaResendEnabled(true);
        }
    },[searchParams])

    useEffect(() => {
        // <%
        //     String proxyContextPath = ServerConfiguration.getInstance().getFirstProperty(IdentityCoreConstants
        //             .PROXY_CONTEXT_PATH);
        //     if (proxyContextPath == null) {
        //         proxyContextPath = "";
        //     }
        // %>
        const PROXY_CONTEXT_PATH: string = "proxy-context-path";
        setProxyContextPath(PROXY_CONTEXT_PATH ?? "")
    },[])

    function goBack() {
        // document.getElementById("restartFlowForm").submit();
    }

    function onCompleted() {
        // $('#loginForm').submit();
    }

    function onSubmit(e: FormEvent) {
        const appName: string = searchParams.get("sp") || "";
        const loginContextRequestUrl: string = logincontextURL + "?sessionDataKey=" + encodeURIComponent(searchParams.get("sessionDataKey") || "") + "&application="
            + encodeURIComponent(appName);

        e.preventDefault();
                
        if (username) {
            let contextPath = proxyContextPath
            if (contextPath !== "") {
                contextPath = contextPath.startsWith('/') ? contextPath : "/" + contextPath
                contextPath = contextPath.endsWith('/') ?
                    contextPath.substring(0, contextPath.length - 1) : contextPath
            }
            
            fetch(contextPath + loginContextRequestUrl,{
                method: 'get',
                credentials: 'include',
            })
            .then(async res => {
                const data = await res.json()
            
                if (data && data.status == 'redirect' && data.redirectUrl && data.redirectUrl.length > 0) {
                    window.location.href = data.redirectUrl;
                } 
            }).catch(err => console.error(err))
        }
    }

    function renderBasicAuthErrorMessage () {
        if (
            searchParams.get("errorCode") === IdentityCoreConstants.USER_ACCOUNT_LOCKED_ERROR_CODE &&
            searchParams.get("remainingAttempts") === "0" 
        ) {
            if (searchParams.get("lockedReason") === "AdminInitiated") {
                return (
                    <div className="ui visible negative message" id="error-msg" data-testid="login-page-error-message">
                        i18n(error.user.account.locked.admin.initiated)
                    </div>
                )
            } else {
                return (
                    <div className="ui visible negative message" id="error-msg" data-testid="login-page-error-message">
                       i18n(error.user.account.locked.incorrect.login.attempts)
                    </div>
                )
            }
        } else if (Boolean(loginFailed) && IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE !== errorCode) {
            return (
                <div className="ui visible negative message" id="error-msg" data-testid="login-page-error-message">
                    i18n(errorMessage)
                </div>
            )
        } else if (searchParams.get("authz_failure") === 'true'){
            return (
                <div className="ui visible negative message" id="error-msg" data-testid="login-page-error-message">
                    i18n(unauthorized.to.login)
                </div>
            )
        } else { 
            return (
                <div className="ui visible negative message" style={{ display: "none" }} id="error-msg" data-testid="login-page-error-message"></div>
            )
        } 
    }

    function temp() {
        if (Boolean(loginFailed) && errorCode === IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE && searchParams.get("resend_username") == null) { 
            return (
                <>
                    <div className="ui visible warning message" id="error-msg" data-testid="login-page-error-message">
                        <form 
                            action={"login.do?resend_username=<%=Encode.forHtml(URLEncoder.encode(request.getParameter(\"failedUsername\"), UTF_8))%>&<%=AuthenticationEndpointUtil.cleanErrorMessages(Encode.forJava(request.getQueryString()))%>"} 
                            method="post" 
                            id="resendForm"
                        >
                            i18n(errorMessage)
                            <div className="ui divider hidden"></div>
                            i18n(no.confirmation.mail)

                            <button id="registerLink"
                                className="resend-button g-recaptcha"
                                data-sitekey={ reCaptchaResendEnabled ? getInitParameter("reCaptchaKey") : ""}
                                data-callback={onSubmitResend}
                                data-action="resendConfirmation"
                                data-testid="login-page-resend-confirmation-email-link"
                            >
                                i18n(resend.mail)
                            </button>
                        </form>
                    </div>
                </>
            )
        }
    }

    function onSubmitResend(token: string) {
        // $("#resendForm").submit();
     }

    function isIdentifierFirstLogin(inputType: string) {
        return "idf" === inputType.toLocaleLowerCase();
    }

    function getRecoverAccountUrl(identityMgtEndpointContext: string, urlEncodedURL: string, isUsernameRecovery: boolean, urlParameters: string): string {
        // return identityMgtEndpointContext + ACCOUNT_RECOVERY_ENDPOINT_RECOVER + "?" + urlParameters
        //         + "&isUsernameRecovery=" + isUsernameRecovery + "&callback=" + Encode
        //         .forHtmlAttribute(urlEncodedURL);
        return "recoveryEPURL"
    }

    function getRecoverAccountUrlWithUsername(identityMgtEndpointContext: string, urlEncodedURL: string,
        isUsernameRecovery: boolean, urlParameters: string, username: string): string {

        // if (StringUtils.isNotBlank(username)) {
        // urlParameters = urlParameters + "&username=" + Encode.forHtmlAttribute(username);
        // }

        // return identityMgtEndpointContext + ACCOUNT_RECOVERY_ENDPOINT_RECOVER + "?" + urlParameters
        //         + "&isUsernameRecovery=" + isUsernameRecovery + "&callback=" + Encode
        //         .forHtmlAttribute(urlEncodedURL);
        return "ree"
    }

    function getRegistrationUrl(accountRegistrationEndpointURL: string, urlEncodedURL: string,
            urlParameters: string) {

        return accountRegistrationEndpointURL + "?" + urlParameters + "&callback=" + encodeURIComponent(urlEncodedURL);
    }

    return (
        <>
            {renderBasicAuthErrorMessage()}
            {temp()}
            <form className="ui large form" action={getLoginFormActionUrl()} method="post" id="loginForm">
                {
                    (getLoginFormActionUrl() === samlssoURL || getLoginFormActionUrl() === oauth2AuthorizeURL) && (
                        <input id="tocommonauth" name="tocommonauth" type="hidden" value="true" />
                    )
                }
    
                {searchParams.get("passwordReset") === 'true' && (
                    <div className="ui visible positive message" data-testid="password-reset-success-message">
                        i18n(Updated.the.password.successfully)
                    </div>
                )}
    
                {
                   !isIdentifierFirstLogin(searchParams.get("inputType") || "") ? (
                        <div className="field">
                            <div className="ui fluid left icon input">
                                <input
                                    type="text"
                                    id="username"
                                    value={username}
                                    name="username"
                                    tabIndex={1}
                                    placeholder="i18n(usernameLabel)"
                                    data-testid="login-page-username-input"
                                    onChange={e => setUsername(e.target.value)}
                                    required 
                                />
                                <i aria-hidden="true" className="user icon"></i>
                            </div>
                        </div>

                    ) : (
                        <input 
                            id="username" 
                            name="username" 
                            type="hidden" 
                            data-testid="login-page-username-input" 
                            value={username} 
                            onChange={e => setUsername(e.target.value)}
                        />
                    )
                }
    
                <div className="field">
                    <div className="ui fluid left icon input addon-wrapper">
                        <input
                            type={passwordInputType}
                            id="password"
                            name="password"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            autoComplete="off"
                            tabIndex={2}
                            placeholder="i18n(password)"
                            data-testid="login-page-password-input"
                            style={{
                                paddingRight: "2.3em !important"
                            }}
                        />
                        <i aria-hidden="true" className="lock icon"></i>
                        <i 
                            id="passwordUnmaskIcon"
                            className="eye icon mr-0"
                            style={{
                                margin: "0 auto", 
                                right: 0, 
                                pointerEvents: "auto", 
                                cursor: "pointer"
                            }}
                            onClick={togglePasswordInputType}
                        ></i>
                    </div>
                </div>

                {
                    reCaptchaEnabled && (
                        <div 
                            className="g-recaptcha"
                            data-size="invisible"
                            data-callback="onCompleted"
                            data-action="login"
                            data-sitekey={getInitParameter("reCaptchaKey")}
                        />
                    )
                }

    {/* TO BE CONVERTED */}
    {/* <%
        Boolean isRecoveryEPAvailable = application.getInitParameter("EnableRecoveryEndpoint");
        Boolean isSelfSignUpEPAvailable = application.getInitParameter("EnableSelfSignUpEndpoint");
        


        if (isRecoveryEPAvailable || isSelfSignUpEPAvailable) {
            String urlWithoutEncoding = null;
            try {
                ApplicationDataRetrievalClient applicationDataRetrievalClient = new ApplicationDataRetrievalClient();
                urlWithoutEncoding = applicationDataRetrievalClient.getApplicationAccessURL(tenantDomain,
                                        request.getParameter("sp"));
                urlWithoutEncoding =  IdentityManagementEndpointUtil.replaceUserTenantHintPlaceholder(
                                                                        urlWithoutEncoding, userTenantDomain);
            } catch (ApplicationDataRetrievalClientException e) {
                //ignored and fallback to login page url
            }

            if (StringUtils.isBlank(urlWithoutEncoding)) {
                String scheme = request.getScheme();
                String serverName = request.getServerName();
                int serverPort = request.getServerPort();
                String uri = (String) request.getAttribute(JAVAX_SERVLET_FORWARD_REQUEST_URI);
                String prmstr = URLDecoder.decode(((String) request.getAttribute(JAVAX_SERVLET_FORWARD_QUERY_STRING)), UTF_8);
                urlWithoutEncoding = scheme + "://" +serverName + ":" + serverPort + uri + "?" + prmstr;
            }

            urlEncodedURL = URLEncoder.encode(urlWithoutEncoding, UTF_8);
            urlParameters = (String) request.getAttribute(JAVAX_SERVLET_FORWARD_QUERY_STRING);

            identityMgtEndpointContext = application.getInitParameter("IdentityManagementEndpointContextURL");
            if (StringUtils.isBlank(identityMgtEndpointContext)) {
                try {
                    identityMgtEndpointContext = ServiceURLBuilder.create().addPath(ACCOUNT_RECOVERY_ENDPOINT).build()
                            .getAbsolutePublicURL();
                } catch (URLBuilderException e) {
                    request.setAttribute(STATUS, AuthenticationEndpointUtil.i18n(resourceBundle, CONFIGURATION_ERROR));
                    request.setAttribute(STATUS_MSG, AuthenticationEndpointUtil
                            .i18n(resourceBundle, ERROR_WHILE_BUILDING_THE_ACCOUNT_RECOVERY_ENDPOINT_URL));
                    request.getRequestDispatcher("error.do").forward(request, response);
                    return;
                }
            }

            accountRegistrationEndpointURL = application.getInitParameter("AccountRegisterEndpointURL");
            if (StringUtils.isBlank(accountRegistrationEndpointURL)) {
                accountRegistrationEndpointURL = identityMgtEndpointContext + ACCOUNT_RECOVERY_ENDPOINT_REGISTER;
            }
        }
    %> */}

    <div className="buttons">
        {
            (isRecoveryEPAvailable && (isUsernameRecoveryEnabledInTenant || isPasswordRecoveryEnabledInTenant)) && (
                <div className="field">
                    i18n(forgot.username.password)
                            
                    {
                        (!isIdentifierFirstLogin(searchParams.get("inputType") || "") && isUsernameRecoveryEnabledInTenant) && (
                        <a
                            id="usernameRecoverLink"
                            tabIndex={5}
                            href="<%=StringEscapeUtils.escapeHtml4(getRecoverAccountUrl(identityMgtEndpointContext, urlEncodedURL, true, urlParameters))%>"
                            data-testid="login-page-username-recovery-button"
                        >
                            i18n(forgot.username)
                        </a>
                        )
                    }

                    {
                        (!isIdentifierFirstLogin(searchParams.get("inputType") || "") && isUsernameRecoveryEnabledInTenant && isPasswordRecoveryEnabledInTenant) &&
                        <p>i18n(forgot.username.password.or)</p>
                    }
                            
                    {
                        isPasswordRecoveryEnabledInTenant && (
                            <a
                                id="passwordRecoverLink"
                                tabIndex={6}
                                href="<%=StringEscapeUtils.escapeHtml4(getRecoverAccountUrlWithUsername(identityMgtEndpointContext, urlEncodedURL, false, urlParameters, usernameIdentifier))%>"
                                data-testid="login-page-password-recovery-button"
                            >
                                i18n(forgot.password)
                            </a>
                        )
                    }
                    ?
                </div>
            )
        }

        {isIdentifierFirstLogin(searchParams.get("inputType") || "") && (
            <div className="field">
                <a 
                    id="backLink" 
                    tabIndex={7} 
                    onClick={goBack} 
                    data-testid="login-page-back-button"
                >
                    i18n(sign.in.different.account)
                </a>
            </div>
        )}     
    </div>

    <div className="ui divider hidden" />

    <div className="field">
        <div className="ui checkbox">
            <input
                tabIndex={3}
                type="checkbox"
                id="chkRemember"
                name="chkRemember"
                data-testid="login-page-remember-me-checkbox"
            />
            <label>i18n(remember.me)</label>
        </div>
    </div>

    <input 
        type="hidden" 
        name="sessionDataKey" 
        value={searchParams.get("sessionDataKey") || ""}
    />

    <div className="ui divider hidden" />

    <div className="cookie-policy-message" data-testid="login-page-policy-messages">
        i18n(privacy.policy.cookies.short.description)
        <a href="cookie_policy.do" target="policy-pane" data-testid="login-page-cookie-policy-link">
            i18n(privacy.policy.cookies)
        </a>
        i18n(privacy.policy.for.more.details)
        <br /><br />
        i18n(privacy.policy.privacy.short.description)
        <a href="privacy_policy.do" target="policy-pane" data-testid="login-page-privacy-policy-link">
            i18n(privacy.policy.general)
        </a>
    </div>

    <div className="ui divider hidden" />

    <div className="mt-0">
        <div className="column buttons">
            <button
                className="ui primary fluid large button"
                tabIndex={4}
                type="submit"
            >
                i18n(continue)
            </button>
        </div>
        <div className="column buttons">
            {
            (isSelfSignUpEPAvailable && !isIdentifierFirstLogin(searchParams.get("inputType") || "") && isSelfSignUpEnabledInTenant) && (
            <button
                type="button"
                onClick={
                    () => {
                        window.location.href = getRegistrationUrl(accountRegistrationEndpointURL, urlEncodedURL, urlParameters);
                    }
                }
                className="ui secondary fluid large button"
                id="registerLink"
                tabIndex={8}
                role="button"
                data-testid="login-page-create-account-button"
            >
                i18n(create.account)
            </button>
            ) 
            }
        </div>
    </div>


            </form>

            <form action={getLoginFormActionUrl()} method="post" id="restartFlowForm">
                <input type="hidden" name="sessionDataKey" value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>'/>
                <input type="hidden" name="restart_flow" value='true'/>
                <input id="tocommonauth" name="tocommonauth" type="hidden" value="true" />
            </form>
        </>
    )
}
