package com.oyea.ebiz.core.security;

import java.util.Collection;
import java.util.Map;

import javax.annotation.Resource;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.HostAuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.AuditorAware;
import org.springframework.stereotype.Service;

import com.brightpoint.directconnect.core.model.integration.api.Product;
import com.brightpoint.directconnect.core.model.offering.Offering;
import com.brightpoint.directconnect.core.model.user.Tenant;
import com.brightpoint.directconnect.core.model.user.User;
import com.brightpoint.directconnect.core.model.user.UserRole;
import com.brightpoint.directconnect.core.service.offering.OfferingService;
import com.brightpoint.directconnect.core.service.user.UserService;
import com.brightpoint.directconnect.core.util.ContextUtil;
import com.brightpoint.directconnect.core.util.Roles;
import com.brightpoint.directconnect.core.util.SessionIdentifiers;

@Service( "SecurityService" )
public class SecurityServiceImpl implements SecurityService, AuditorAware<User> {
	private static final Logger logger = LoggerFactory.getLogger( SecurityService.class );
	private static final String sysAdminUserName = "sysadmin";

	@Resource
	private ContextUtil contextUtil;

	@Resource
	private OfferingService offeringService;
	@Resource
	private UserService userService;

	@Override
	public boolean login( final String username, final char[] password ) {
		return usernamePasswordLogin( username, password, false, contextUtil.getHostname() );
	}

	@Override
	public boolean login( final String username, final char[] password, final boolean rememberMe ) {
		return usernamePasswordLogin( username, password, rememberMe, contextUtil.getHostname() );
	}

	@Override
	public boolean login( final String username, final char[] password, final boolean rememberMe, final String host ) {
		return usernamePasswordLogin( username, password, rememberMe, host );
	}

	@Override
	public boolean login( final char[] authenticationToken ) {
		return hashLogin( authenticationToken );
	}

	private boolean hashLogin( final char[] authToken ) {
		final HashAuthenticationToken token = new ClientAuthenticationToken( authToken, contextUtil.getHostname() );
		return commonLogin( token );
	}

	private boolean usernamePasswordLogin( final String username,
			final char[] password,
			final boolean rememberMe,
			final String host ) {
		final UsernamePasswordToken token = new AdminToolAuthenticationToken( username, password, rememberMe, host );
		return commonLogin( token );
	}

	private boolean commonLogin( final HostAuthenticationToken token ) {
		boolean retVal = false;
		final Subject currentUser = getSubject();
		try {
			currentUser.login( token );
			retVal = true;
			// the following exceptions are just a few you can catch and handle
			// accordingly. See the
			// AuthenticationException JavaDoc and its subclasses for more.
		}
		catch( final IncorrectCredentialsException ice ) {
			logger.error( "Password '%s' is incorrect.", token.getCredentials() );
		}
		catch( final UnknownAccountException uae ) {
			logger.error( "There is no account with username '%s'.", token.getPrincipal() );
		}
		catch( final AuthenticationException ae ) {
			logger.error( "Invalid username and/or password." );
		}
		return retVal;
	}

	private Subject getSubject() {
		return SecurityUtils.getSubject();
	}

	@Override
	public void logout() {
		getSubject().logout();
	}

	@Override
	public User getCurrentAuditor() {
		// Authentication check copied from earlier implementation
		// TODO Investigate if authentication check is necessary
		return isCurrentUserAuthenticated() ? getCurrentUser() : null;
	}

	@Override
	public Long getCurrentUserId() {
		PrincipalCollection principals = getSubject().getPrincipals();
		if( principals == null )
			return null;

		return principals.oneByType( Long.class );
	}

	@Override
	public User getCurrentUser() {
		return getSubjectUser();
	}

	private User getSubjectUser() {
		Long userId = getCurrentUserId();
		return userId != null ? userService.getUserById( userId ) : null;
	}

	@Override
	public Collection<UserRole> getCurrentUserRoles() {
		return getSubjectUser().getUserRoles();
	}

	@Override
	public Tenant getCurrentTenant( final Roles role ) {
		Tenant retVal = null;
		Collection<UserRole> userRoles = getCurrentUserRoles();
		if( userRoles != null && userRoles.size() > 0 ) {
			for( final UserRole userRole : userRoles ) {
				if( userRole.getEnabled() && userRole.getRole().getName().equals( role.getName() ) ) {
					retVal = userRole.getTenant();
					break;
				}
			}
		}
		return retVal;
	}

	@Override
	public Tenant getCurrentServiceOrWebTenant() {
		Tenant serviceTenant = getCurrentTenant( Roles.SERVICE_CLIENT );
		if( serviceTenant != null )
			return serviceTenant;

		Tenant webTenant = getCurrentTenant( Roles.WEB_CLIENT );
		if( webTenant != null )
			return webTenant;

		throw new IllegalArgumentException( "Tenant information not found for the user logged on." );
	}

	@Override
	public Session getSession( final SessionKey sessionKey ) {
		return SecurityUtils.getSecurityManager().getSession( sessionKey );
	}

	@Override
	public Session getSession() {
		return getSubject().getSession();
	}

	@Override
	public Session getSessionWithoutCreate() {
		return getSubject().getSession( false );
	}

	@Override
	public boolean isCurrentUserAuthenticated() {
		return getSubject().isAuthenticated();
	}

	@Override
	public boolean isCurrentUserSysAdmin() {
		return isUserSysAdmin( getCurrentUser() );
	}

	@Override
	public boolean isUserSysAdmin( final User user ) {
		return user != null && sysAdminUserName.equals( user.getUserName() );
	}

	@Deprecated
	private Object getSelectedOffer() {
		Session session = getSession();
		Object offers = session.getAttribute( SessionIdentifiers.OFFERS );
		Object product = session.getAttribute( SessionIdentifiers.PRODUCT );

		if( offers == null || product == null ) {
			throw new IllegalArgumentException( "No Offer or Product found in session. This does not appear to be a web shop session! SessionIdentifier: [" +
					offers + "], Product: [" + product + "]" );
		}
		else {
			@SuppressWarnings( "unchecked" )
			Product<String> selectedProduct = (Product<String>) product;
			@SuppressWarnings( "unchecked" )
			Map<String, Object> offersMap = (Map<String, Object>) offers;
			return offersMap.get( selectedProduct.getId() );
		}
	}

	@Deprecated
	@Override
	public Offering getCurrentOfferingFromSession() {
		Object offer = getSelectedOffer();
		try {
			Long offeringId = (Long) PropertyUtils.getProperty( offer, "selectedOffering.id" );
			return offeringService.getById( offeringId );
		}
		catch( final Exception exception ) {
			logger.error( "Could not find selected offering", exception );
		}
		return null;
	}
}
