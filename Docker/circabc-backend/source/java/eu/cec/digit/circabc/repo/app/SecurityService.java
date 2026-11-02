package eu.cec.digit.circabc.repo.app;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.esapi.ESAPI;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.validator.html.*;
import org.springframework.web.util.HtmlUtils;

import java.io.File;

public class SecurityService {

    private static final Log logger = LogFactory.getLog(SecurityService.class);
    private static final String lineSeparator = System.getProperty("line.separator");
    private static String POLICY_FILE_LOCATION =
            System.getProperty("user.home")
                    + File.separator
                    + "esapi"
                    + File.separator
                    + "antisamy-esapi.xml";
    private Policy policy;
    private AntiSamy antiSamy;

    /**
     * Allowlist-based HTML sanitizer built with the OWASP Java HTML Sanitizer.
     * Permits common safe formatting / structural tags and their typical
     * attributes while stripping everything else (scripts, event handlers,
     * javascript: URIs, etc.).
     */
    private static final PolicyFactory HTML_SANITIZER_POLICY = new HtmlPolicyBuilder()
            // Block-level elements
            .allowElements(
                    "p", "div", "span", "br", "hr",
                    "h1", "h2", "h3", "h4", "h5", "h6",
                    "ul", "ol", "li", "dl", "dt", "dd",
                    "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col",
                    "blockquote", "pre", "code",
                    "strong", "em", "b", "i", "u", "s", "sub", "sup",
                    "a", "img",
                    "abbr", "cite", "q")
            // Allow safe attributes
            .allowAttributes("class", "id", "title", "lang", "dir").globally()
            .allowAttributes("href").onElements("a")
            .allowAttributes("src", "alt", "width", "height").onElements("img")
            .allowAttributes("colspan", "rowspan", "scope", "headers").onElements("th", "td")
            .allowAttributes("align", "valign").onElements(
                    "table", "thead", "tbody", "tfoot", "tr", "th", "td")
            .allowAttributes("border", "cellpadding", "cellspacing", "summary").onElements("table")
            .allowAttributes("span").onElements("col", "colgroup")
            .allowAttributes("start", "type").onElements("ol")
            .allowAttributes("cite").onElements("blockquote", "q")
            .allowAttributes("target").onElements("a")
            // Only allow safe URL protocols
            .allowUrlProtocols("http", "https", "mailto")
            .requireRelNofollowOnLinks()
            .toFactory();

    private void init() {
        if (policy == null) {
            try {
                policy = Policy.getInstance(POLICY_FILE_LOCATION);
            } catch (PolicyException e) {
                if (logger.isErrorEnabled()) {
                    logger.error("Error creating policy " + POLICY_FILE_LOCATION, e);
                }
            }
            antiSamy = new AntiSamy();
        }
    }

    /**
     * Sanitize the input using an allowlist-based OWASP Java HTML Sanitizer.
     * Before sanitizing, the ESAPI canonicalize step is applied to defeat
     * double-encoding bypass attacks.
     *
     * <p>This replaces the former regex blocklist approach which was fragile
     * and missed many XSS vectors (onerror, onmouseover, onclick, etc.).</p>
     */
    private String stripXSS(String value) {
        if (value == null) {
            return null;
        }

        // Canonicalize to defeat double-encoding / mixed-encoding bypass attacks
        try {
            value = ESAPI.encoder().canonicalize(value);
        } catch (Exception e) {
            // If canonicalization fails (e.g. intrusion detected), log and
            // continue with the original value – the HTML sanitizer below
            // will still strip dangerous content.
            if (logger.isWarnEnabled()) {
                logger.warn("ESAPI canonicalize failed, proceeding with raw value", e);
            }
        }

        // Apply the allowlist-based HTML sanitizer – everything not explicitly
        // allowed (scripts, event-handler attributes, javascript: URIs, etc.)
        // is automatically removed.
        value = HTML_SANITIZER_POLICY.sanitize(value);

        return value;
    }

    private String runAntiSamy(String value) {
        String result = value;
        CleanResults cleanValue = null;

        if (value != null) {
            init();

            try {
                cleanValue = antiSamy.scan(value, policy, AntiSamy.SAX);
            } catch (ScanException e) {
                if (logger.isErrorEnabled()) {
                    logger.error("Scan error" + POLICY_FILE_LOCATION, e);
                }
            } catch (PolicyException e) {
                if (logger.isErrorEnabled()) {
                    logger.error("Policy error " + POLICY_FILE_LOCATION, e);
                }
            }
        }

        if (cleanValue != null) {
            final String cleanHTML = cleanValue.getCleanHTML();
            final String htmlUnescape = HtmlUtils.htmlUnescape(cleanHTML);
            // check if antisamy just escaped characters
            if (!htmlUnescape.equals(result)) {
                result = cleanHTML;
            }
        } else {
            result = "";
        }
        return result;
    }

    /**
     * @param value          The string input.
     * @param permissiveHtml Set to true and it will ignore the antisamyRun
     */
    public String getCleanHTML(String value, Boolean permissiveHtml) {

        boolean checkPermissiveHtml = (permissiveHtml != null && permissiveHtml);

        String result = stripXSS(value);

        if (!checkPermissiveHtml) {
            result = runAntiSamy(result);
        }

        return result;
    }

    /**
     * Verify if the provided text corresponds to the cleaned text by antisamy & stripXss. If yes, the
     * text is valid.
     *
     * @param value          value The string input.
     * @param permissiveHtml permissiveHtml Set to true and it will ignore the antisamyRun
     */
    public boolean isCleanHTML(String value, Boolean permissiveHtml) {
        if (value == null) {
            return true;
        }
        value = value.replaceAll("\\r\\n", lineSeparator);
        return value.equalsIgnoreCase(getCleanHTML(value, permissiveHtml));
    }
}
