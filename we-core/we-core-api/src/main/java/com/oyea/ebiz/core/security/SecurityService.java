package com.oyea.ebiz.core.security;

import java.util.Collection;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionKey;

import com.brightpoint.directconnect.core.model.offering.Offering;
import com.brightpoint.directconnect.core.model.user.Tenant;
import com.brightpoint.directconnect.core.model.user.User;
import com.brightpoint.directconnect.core.model.user.UserRole;
import com.brightpoint.directconnect.core.util.Roles;

// @formatter:off
public interface SecurityService {
    boolean login(String username, char[] password);
    boolean login(String username, char[] password, boolean rememberMe);
    boolean login(String username, char[] password, boolean rememberMe, String host);
    boolean login(char[] authenticationToken);

    void logout();

    Long getCurrentUserId();
    User getCurrentUser();

    Collection<UserRole> getCurrentUserRoles();

    Tenant getCurrentTenant(Roles roleType);
    Tenant getCurrentServiceOrWebTenant();

    Session getSession();
    Session getSessionWithoutCreate();
    Session getSession(SessionKey id);

    boolean isCurrentUserAuthenticated();
    boolean isCurrentUserSysAdmin();
    boolean isUserSysAdmin( final User user );


	/**
	 * @deprecated This is just a temporary hack to get rid of another hack. Values should be sent to the integration modules
	 */
	@Deprecated
	Offering getCurrentOfferingFromSession();
}
