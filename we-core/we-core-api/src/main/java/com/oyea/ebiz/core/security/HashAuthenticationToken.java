package com.oyea.ebiz.core.security;

import org.apache.shiro.authc.HostAuthenticationToken;

/**
 * Extension of Shiro's {@link HostAuthenticationToken} by defining a security
 * hash
 * <p>
 * © 2012 BrightPoint. All rights reserved. Used by permission.
 * </p>
 * 
 * @author Vladimir Petrov
 * @version 1.0
 * @since 1.0
 */
public interface HashAuthenticationToken extends HostAuthenticationToken {

    /**
     * Retrieves authentication hash
     * 
     * @return authentication hash as a char array
     */
    char[] getHash();
}
