package com.oyea.ebiz.core.security;

public class ClientAuthenticationToken implements HashAuthenticationToken {
    private static final long serialVersionUID = 8786147934709548756L;
    private char[] hash;
    private String host;

    public ClientAuthenticationToken() {
        super();
        host = null;
        hash = null;
    }

    public ClientAuthenticationToken(final char[] hash) {
        super();
        this.hash = hash.clone();
        host = null;
    }

    public ClientAuthenticationToken(final char[] hash, final String host) {
        super();
        this.hash = hash.clone();
        this.host = host;
    }

    @Override
    public char[] getHash() {
        return hash.clone();
    }

    public void setHash(final char[] hash) {
        this.hash = hash.clone();
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public Object getPrincipal() {
        // TODO Auto-generated method stub
        return hash.clone();
    }

    @Override
    public Object getCredentials() {
        return hash.clone();
    }
}
