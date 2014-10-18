package com.oyea.ebiz.core.security;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.brightpoint.directconnect.core.util.CryptoService;

public class CryptoServiceImpl implements CryptoService {
	@Autowired
	private SecurityService securityService;

    @Override
    public String getRsaPublicKeyAsString() {
        return Base64.encodeToString(CryptographyUtil.getRSAPublicKeyAsString().getBytes());
    }

    @Override
    public byte[] getRsaPublicKey() {
        return CryptographyUtil.getRSAPublicKey();
    }

    @Override
    public void aesKeyExtract(final byte[] rsaCryptedAesKey) {
        CryptographyUtil.extractAESKey(getIdentifier(), rsaCryptedAesKey);
    }

    @Override
    public String aesEncrypt(final String plainMessage) {
        return CryptographyUtil.encryptAESMessage(getIdentifier(), plainMessage);
    }

    @Override
    public String aesDecrypt(final String encryptedMessage) {
        return CryptographyUtil.decryptAESMessage(getIdentifier(), encryptedMessage);
    }

    @Override
    public byte[] rsaDecrypt(final byte[] encryptedMessage) {
        return CryptographyUtil.decryptRSAString(encryptedMessage);
    }

    private String getIdentifier() {
        Session session = securityService.getSession();
        return session.getId().toString();
    }
}
