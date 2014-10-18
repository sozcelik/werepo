package com.oyea.ebiz.core.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.brightpoint.directconnect.core.model.user.Permission;
import com.brightpoint.directconnect.core.model.user.User;
import com.brightpoint.directconnect.core.model.user.UserRole;
import com.brightpoint.directconnect.core.service.user.UserService;
import com.brightpoint.directconnect.core.util.Placeholder.Security;

@Service
@Transactional(readOnly = true)
public class ClientSecurityRealm extends AuthorizingRealm {
	public static String NAME = "clientSecurityRealm";

	@Autowired
	private UserService userService;

	private static final String PERM_SEP = ":";

	public ClientSecurityRealm() {
		setName( NAME );
	}

	@Override
	public boolean supports( final AuthenticationToken token ) {
		return token instanceof ClientAuthenticationToken;
	}
    
    @Override
    public void checkPermission(final PrincipalCollection subjectIdentifier, final String permission)
                    throws AuthorizationException {
        Collection<UserRole> userRoles = subjectIdentifier.byType(UserRole.class);
        Iterator<UserRole> userRolesIter = userRoles.iterator();
        while (userRolesIter.hasNext()) {
            UserRole userRole = userRolesIter.next();
            super.checkPermission(subjectIdentifier, getPermissionString(userRole.getTenant().getName(), permission));
        }
    }

    @Override
    public boolean isPermitted(final PrincipalCollection principals, final String permission) {
        Collection<UserRole> userRoles = principals.byType(UserRole.class);
        Iterator<UserRole> userRolesIter = userRoles.iterator();
        while (userRolesIter.hasNext()) {
            UserRole userRole = userRolesIter.next();
            if (super.isPermitted(principals, getPermissionString(userRole.getTenant().getName(), permission))) {
                return true;
            }               
        }
        return false;
    }
    
    private String getPermissionString(final String tenant , final String permission) {       
        return tenant + PERM_SEP + permission;
    }

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo( final AuthenticationToken token ) throws AuthenticationException {
		AuthenticationInfo retVal = null;
		ClientAuthenticationToken hashedToken = (ClientAuthenticationToken) token;
		char[] hash = hashedToken.getHash();
		User user = userService.getUserByAuthenticationToken( new String( hash ) );
		if( user != null ) {
			retVal = new SimpleAuthenticationInfo( user.getId(), hash, getName() );
		}
		return retVal;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo( final PrincipalCollection principals ) {
		SimpleAuthorizationInfo info = null;
		Long userId = (Long) principals.fromRealm( getName() ).iterator().next();
		User user = userService.getUserById( userId );
		if( user != null ) {
			info = new SimpleAuthorizationInfo();
			info.addStringPermission( Security.CLIENT_PERMISSION );
			for( final UserRole userRole : user.getUserRoles() ) {
				if( userRole.getEnabled() ) {
					info.addRole( userRole.getRole().getName() + PERM_SEP + userRole.getTenant().getName() );
					info.addObjectPermissions( getPermissions( userRole.getRole().getPermissions(), userRole.getTenant().getName() ) );
				}
			}
		}
		return info;
	}
    
    private Collection<org.apache.shiro.authz.Permission> getPermissions(final List<Permission> permissions,
                    final String tenant) {
        Collection<org.apache.shiro.authz.Permission> retVal = new ArrayList<org.apache.shiro.authz.Permission>();
        if (permissions != null) {
            for (Permission permission : permissions) {
                retVal.add(new WildcardPermission(tenant + PERM_SEP + permission.getAccessCode()));
            }  
        } 
        return retVal;
    }
}
