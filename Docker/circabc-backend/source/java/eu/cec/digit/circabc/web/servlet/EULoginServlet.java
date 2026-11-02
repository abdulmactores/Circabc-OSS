package eu.cec.digit.circabc.web.servlet;

import eu.cec.digit.circabc.model.UserModel;
import eu.cec.digit.circabc.service.CircabcServiceRegistry;
import eu.cec.digit.circabc.service.log.LogRecord;
import eu.cec.digit.circabc.service.log.LogService;
import eu.cec.digit.circabc.service.struct.ManagementService;
import eu.cec.digit.circabc.service.user.UserService;
import eu.cec.digit.circabc.util.CircabcUserDataBean;
import eu.cec.digit.circabc.web.Services;
import eu.cec.digit.ecas.client.jaas.DetailedUser;
import org.alfresco.model.ContentModel;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.web.app.servlet.BaseServlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

/**
 * Servlet handling the EU Login (ECAS) SSO callback.
 *
 * <h3>Security hardening (2024)</h3>
 * <ul>
 *   <li>Cookies now carry {@code SameSite=Strict}, {@code HttpOnly}, and
 *       {@code Secure} attributes to mitigate CSRF and XSS-based session
 *       theft.</li>
 *   <li>A cryptographically random CSRF token is generated on login and
 *       set as a {@code csrf_token} cookie. The Angular frontend should
 *       read this value and include it as an {@code X-CSRF-Token} header
 *       on every state-changing request. Server-side filters should
 *       validate the header against the cookie.</li>
 * </ul>
 *
 * <h3>Future enhancement – OAuth2 PKCE flow</h3>
 * <p>The current cookie-based authentication should be migrated to an
 * OAuth2 Authorization Code flow with PKCE (RFC 7636). This would
 * eliminate the need for cookie-based session tokens entirely and
 * provide a standards-based, stateless authentication mechanism:
 * <ol>
 *   <li>Register CIRCABC as an OAuth2 / OIDC client with EU Login.</li>
 *   <li>Replace this servlet's redirect logic with an Authorization
 *       Code + PKCE exchange.</li>
 *   <li>Issue short-lived JWTs (access tokens) validated on each API
 *       call, with refresh tokens stored securely.</li>
 *   <li>Remove the username/ticket cookie mechanism once the Angular
 *       frontend is updated to use Bearer token authentication.</li>
 * </ol>
 * </p>
 */
public class EULoginServlet extends BaseServlet {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int CSRF_TOKEN_BYTES = 32;

    private UserService userService;
    private PersonService personService;
    private NodeService nodeService;

    private ManagementService managementService;
    private LogService logService;


    @Override
    public void init() throws ServletException {

        super.init();

        personService = Services.getAlfrescoServiceRegistry(getServletContext()).
                getPersonService();

        nodeService = Services.getAlfrescoServiceRegistry(getServletContext()).
                getNodeService();

        logService = (LogService)
                Services.getCircabcServiceRegistry(getServletContext()).
                        getService(CircabcServiceRegistry.NON_SECURED_LOG_SERVICE);

        managementService = (ManagementService)
                Services.getCircabcServiceRegistry(getServletContext()).
                        getService(CircabcServiceRegistry.MANAGEMENT_SERVICE);

        userService = (UserService)
                Services.getCircabcServiceRegistry(getServletContext()).
                        getService(CircabcServiceRegistry.CIRCABC_USER_SERVICE);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        final LogRecord logRecord = new LogRecord();

        final Principal userPrincipal = request.getUserPrincipal();
        String userName = userPrincipal.getName();
        logRecord.setService("Directory");
        logRecord.setActivity("Login");
        logRecord.setUser(userName);
        try {
            AuthenticationUtil.setRunAsUserSystem();
            if (!personService.personExists(userName)) {
                final CircabcUserDataBean user = new CircabcUserDataBean();
                user.setUserName(userName);

                final CircabcUserDataBean ldapUserDetail = userService.getLDAPUserDataByUid(userName);
                user.copyLdapProperties(ldapUserDetail);
                if (ldapUserDetail == null) {
                    if (userPrincipal instanceof DetailedUser) {
                        DetailedUser detailedUser = (DetailedUser) userPrincipal;
                        user.copyDetailedUserProperties(detailedUser);
                    }
                }
                userService.createUser(user, true);
            } else {
                final CircabcUserDataBean ldapUserDetail = userService.getLDAPUserDataByUid(userName);
                if (ldapUserDetail != null) {
                    Date ldapTime = ldapUserDetail.getLastModificationDetailsTime();
                    if (ldapTime != null) {
                        final NodeRef nodeRef = personService.getPerson(userName);
                        Date repoTime = (Date) nodeService
                                .getProperty(nodeRef, UserModel.PROP_LAST_MODIFICATION_DETAILS_TIME);
                        if (repoTime == null || ldapTime.after(repoTime)) {
                            final CircabcUserDataBean repoUser = userService.getCircabcUserDataBean(userName);
                            repoUser.copyLdapProperties(ldapUserDetail);
                            userService.updateUser(repoUser);
                        }

                    }
                }

            }
        } finally {
            AuthenticationUtil.setRunAsUser(userName);
        }

        try {
            AuthenticationUtil.setRunAsUserSystem();
            final NodeRef circabcNodeRef = managementService.getCircabcNodeRef();
            logRecord
                    .setIgID((Long) nodeService.getProperty(circabcNodeRef, ContentModel.PROP_NODE_DBID));
            logRecord.setIgName((String) nodeService.getProperty(circabcNodeRef, ContentModel.PROP_NAME));
        } finally {
            AuthenticationUtil.setRunAsUser(userName);
        }

        final String ticket = userService.getCurrentTicket(userName);

        logRecord.setOK(true);
        logService.log(logRecord);

        // Set username cookie with SameSite=Strict via Set-Cookie header
        // (javax.servlet.http.Cookie does not support SameSite natively)
        addHardenedCookie(response, "username", userName, 120, true);

        // Set ticket cookie with SameSite=Strict
        addHardenedCookie(response, "ticket", ticket, 120, true);

        // Generate a CSRF token so the Angular frontend can include it as
        // an X-CSRF-Token header on state-changing requests.
        // The csrf_token cookie is NOT HttpOnly so JavaScript can read it.
        String csrfToken = generateCsrfToken();
        addHardenedCookie(response, "csrf_token", csrfToken, 120, false);

        response.sendRedirect(request.getContextPath() + "/ui/welcome");
    }

    /**
     * Adds a cookie to the response with hardened security attributes.
     * <p>
     * Because the standard {@code javax.servlet.http.Cookie} API (Servlet 3.x) does not expose
     * a {@code SameSite} setter, we build the {@code Set-Cookie} header
     * manually so we can include {@code SameSite=Strict}.
     * </p>
     *
     * @param response   the HTTP response
     * @param name       cookie name
     * @param value      cookie value
     * @param maxAgeSecs lifetime in seconds
     * @param httpOnly   whether the cookie should be {@code HttpOnly}
     *                   (set to {@code false} for the CSRF token so the
     *                   Angular frontend can read it via JavaScript)
     */
    private static void addHardenedCookie(HttpServletResponse response,
                                          String name,
                                          String value,
                                          int maxAgeSecs,
                                          boolean httpOnly) {
        StringBuilder sb = new StringBuilder(128);
        sb.append(name).append('=').append(value);
        sb.append("; Path=/");
        sb.append("; Max-Age=").append(maxAgeSecs);
        sb.append("; Secure");
        sb.append("; SameSite=Strict");
        if (httpOnly) {
            sb.append("; HttpOnly");
        }
        response.addHeader("Set-Cookie", sb.toString());
    }

    /**
     * Generates a cryptographically strong random CSRF token.
     *
     * @return a Base64-URL-encoded token string (no padding)
     */
    private static String generateCsrfToken() {
        byte[] bytes = new byte[CSRF_TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}