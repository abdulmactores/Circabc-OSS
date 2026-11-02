/**
 * ***************************************************************************** Copyright 2006
 * European Community
 *
 * <p>Licensed under the EUPL, Version 1.1 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * <p>https://joinup.ec.europa.eu/software/page/eupl
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * ****************************************************************************
 */
package eu.cec.digit.circabc.repo.iam;

import eu.cec.digit.circabc.service.iam.IamWSClient;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class IamWSClientImpl implements IamWSClient {

    private static final int NONCE_BYTE_LENGTH = 16;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final int CONNECTION_TIMEOUT_10_S = 10000;

    private static final Log logger = LogFactory.getLog(IamWSClientImpl.class);

    private static final ThreadLocal<DateFormat> DATE_FORMAT =
            new ThreadLocal<DateFormat>() {
                @Override
                protected DateFormat initialValue() {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
                    sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
                    return sdf;
                }
            };

    private static final String DATA_TEMPLATE_GRANT_THEM_ROLE =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                    + "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"\r\n"
                    + "	xmlns:v3=\"http://ec.europa.eu/rdg/efp/services/iam/research-theme/interfaces/V3\">\r\n"
                    + "	<soap:Header>\r\n"
                    + "		<wsse:Security\r\n"
                    + "			xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">\r\n"
                    + "			<wsse:UsernameToken wsu:Id=\"UsernameToken-1\"\r\n"
                    + "				xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\r\n"
                    + "				<wsse:Username>%1$s</wsse:Username>\r\n"
                    + "				<wsse:Password\r\n"
                    + "					Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%2$s</wsse:Password>\r\n"
                    + "				<wsse:Nonce\r\n"
                    + "					EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%3$s</wsse:Nonce>\r\n"
                    + "				<wsu:Created>%4$s</wsu:Created>\r\n"
                    + "			</wsse:UsernameToken>\r\n"
                    + "		</wsse:Security>\r\n"
                    + "	</soap:Header>\r\n"
                    + "	<soap:Body>\r\n"
                    + "		<v3:grantThemeRole>\r\n"
                    + "			<v3:UserId>%5$s</v3:UserId>\r\n"
                    + "			<v3:ThemeId>%6$s</v3:ThemeId>\r\n"
                    + "			<v3:Role>%7$s</v3:Role>\r\n"
                    + "		</v3:grantThemeRole>\r\n"
                    + "	</soap:Body>\r\n"
                    + "</soap:Envelope>";

    private static final String DATA_TEMPLATE_REVOKE_THEM_ROLE =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                    + "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"\r\n"
                    + "	xmlns:v3=\"http://ec.europa.eu/rdg/efp/services/iam/research-theme/interfaces/V3\">\r\n"
                    + "	<soap:Header>\r\n"
                    + "		<wsse:Security\r\n"
                    + "			xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">\r\n"
                    + "			<wsse:UsernameToken wsu:Id=\"UsernameToken-1\"\r\n"
                    + "				xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\r\n"
                    + "				<wsse:Username>%1$s</wsse:Username>\r\n"
                    + "				<wsse:Password\r\n"
                    + "					Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%2$s</wsse:Password>\r\n"
                    + "				<wsse:Nonce\r\n"
                    + "					EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%3$s</wsse:Nonce>\r\n"
                    + "				<wsu:Created>%4$s</wsu:Created>\r\n"
                    + "			</wsse:UsernameToken>\r\n"
                    + "		</wsse:Security>\r\n"
                    + "	</soap:Header>\r\n"
                    + "	<soap:Body>\r\n"
                    + "		<v3:revokeThemeRole>\r\n"
                    + "			<v3:UserId>%5$s</v3:UserId>\r\n"
                    + "			<v3:ThemeId>%6$s</v3:ThemeId>\r\n"
                    + "			<v3:Role>%7$s</v3:Role>\r\n"
                    + "		</v3:revokeThemeRole>\r\n"
                    + "	</soap:Body>\r\n"
                    + "</soap:Envelope>";

    private String serviceUrl;
    private String user;
    private String password;

    private static byte[] getNonceBytes() {
        byte[] nonce = new byte[NONCE_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(nonce);
        return nonce;
    }

    private static String calculatePasswordDigest(byte[] nonceBytes, String created, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(nonceBytes);
            md.update(created.getBytes(StandardCharsets.UTF_8));
            md.update(password.getBytes(StandardCharsets.UTF_8));
            byte[] encodedPassword = md.digest();

            return new String(Base64.encodeBase64(encodedPassword));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm not available in the JVM", ex);
        }
    }

    public String getServiceUrl() {
        return serviceUrl;
    }

    public void setServiceUrl(String serviceUrl) {
        this.serviceUrl = serviceUrl;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public void grantThemeRole(String userName, String themeID, String roleID) {
        callWebService(userName, themeID, roleID, DATA_TEMPLATE_GRANT_THEM_ROLE);
    }

    @Override
    public void revokeThemeRole(String userName, String themeID, String roleID) {
        callWebService(userName, themeID, roleID, DATA_TEMPLATE_REVOKE_THEM_ROLE);
    }

    private void callWebService(String userID, String themeID, String roleID, String dataTemplate) {
        HttpClient httpClient = new HttpClient();
        httpClient.getParams().setParameter("http.useragent", "IAM Web Service Client");
        PostMethod methodPost = new PostMethod(serviceUrl);

        byte[] nonceBytes = getNonceBytes();
        String nonceEncoded = new String(Base64.encodeBase64(nonceBytes));
        String created = DATE_FORMAT.get().format(new Date());
        String digest = calculatePasswordDigest(nonceBytes, created, password);
        String data =
                String.format(dataTemplate, user, digest, nonceEncoded, created, userID, themeID, roleID);

        methodPost.setRequestBody(data);

        methodPost.setRequestHeader("Content-Type", "text/xml");

        try {

            httpClient.getParams().setSoTimeout(CONNECTION_TIMEOUT_10_S);
            int returnCode = httpClient.executeMethod(methodPost);

            if (returnCode == HttpStatus.SC_NOT_IMPLEMENTED) {
                if (logger.isErrorEnabled()) {
                    logger.error("The Post method is not implemented by this URI: " + serviceUrl);
                }
            } else {
                String response = methodPost.getResponseBodyAsString();
                if (logger.isInfoEnabled()) {
                    logger.info("Request:\n" + data);
                    logger.info("Response:\n" + response);
                }
                if (!response.contains("SUCCESSFUL")) {
                    if (logger.isErrorEnabled()) {
                        logger.error("Call IAM  web service :  " + data);
                        logger.error("Response is not successfull :" + response);
                    }
                    throw new IamWSEception("Response is not successfull :" + response);
                }
            }

        } catch (HttpException e) {
            if (logger.isErrorEnabled()) {
                logger.error("Error Accessing IAM webservice: " + serviceUrl, e);
            }
            throw new IamWSEception("Http Exception", e);

        } catch (IOException e) {
            if (logger.isErrorEnabled()) {
                logger.error("Error Accessing IAM webservice: " + serviceUrl, e);
            }
            throw new IamWSEception("IOException", e);

        } finally {

            methodPost.releaseConnection();
        }
    }
}
