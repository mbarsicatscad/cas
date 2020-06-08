package org.apereo.cas.adaptors.duo.web.flow.action;

import org.apereo.cas.adaptors.duo.authn.DuoSecurityCredential;
import org.apereo.cas.adaptors.duo.authn.DuoSecurityMultifactorAuthenticationProvider;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.apereo.cas.web.support.WebUtils;

import lombok.val;
import org.springframework.context.ApplicationContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.util.Objects;

/**
 * This is {@link DuoSecurityPrepareWebLoginFormAction}.
 *
 * @author Misagh Moayyed
 * @since 5.1.0
 */
public class DuoSecurityPrepareWebLoginFormAction extends AbstractMultifactorAuthenticationAction<DuoSecurityMultifactorAuthenticationProvider> {

    public DuoSecurityPrepareWebLoginFormAction(final ApplicationContext applicationContext) {
        super(applicationContext);
    }

    @Override
    protected Event doExecute(final RequestContext requestContext) {
        val principal = (val) WebUtils.getAuthentication(requestContext).getPrincipal();
        //val credential = (val) WebUtils.getCredential(requestContext, DuoSecurityCredential.class);
        val credential = requestContext.getFlowScope().get(CasWebflowConstants.VAR_ID_CREDENTIAL, DuoSecurityCredential.class);
        if (credential == null) {
            System.out.println("MJB Debug credential is null");
            logger.warn("credential is null");
        } else {
            System.out.println("MJB Debug credential = " + credential.toString())
            logger.debug("credential = " + credential.toString());
        }
        credential.setUsername(principal.getId());
        credential.setProviderId(provider.createUniqueId());

        val duoAuthenticationService = provider.getDuoAuthenticationService();
        val viewScope = requestContext.getViewScope();
        viewScope.put("sigRequest", duoAuthenticationService.signRequestToken(principal.getId()));
        viewScope.put("apiHost", duoAuthenticationService.getApiHost());
        viewScope.put("commandName", "credential");
        viewScope.put("principal", principal);
        return success();
    }
}
