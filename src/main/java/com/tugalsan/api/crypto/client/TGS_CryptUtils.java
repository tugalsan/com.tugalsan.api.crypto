package com.tugalsan.api.crypto.client;

import com.googlecode.gwt.crypto.bouncycastle.DataLengthException;
import com.googlecode.gwt.crypto.bouncycastle.InvalidCipherTextException;
import com.googlecode.gwt.crypto.bouncycastle.util.encoders.Base64;
import com.googlecode.gwt.crypto.client.TripleDesCipher;
import com.tugalsan.api.bytes.client.TGS_ByteArrayUtils;
import com.tugalsan.api.charset.client.*;
import java.io.UnsupportedEncodingException;

public class TGS_CryptUtils {

    public static String encrypt64_orEmpty(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        try {
            return new String(Base64.encode(bytes), TGS_CharSetUTF8.UTF8);
        } catch (UnsupportedEncodingException ex) {
            return "";
        }
    }

    public static String encrypt64_orEmpty(CharSequence inputString) {
        if (inputString == null || inputString.toString().isEmpty()) {
            return "";
        }
        return encrypt64_orEmpty(TGS_ByteArrayUtils.toByteArray(inputString));
    }

    public static byte[] decrypt64_toBytes(CharSequence inputBase64) {
        if (inputBase64 == null || inputBase64.toString().isEmpty()) {
            return null;
        }
        return Base64.decode(TGS_ByteArrayUtils.toByteArray(inputBase64));
    }

    public static String decrypt64_orEmpty(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        try {
            return new String(Base64.decode(bytes), TGS_CharSetUTF8.UTF8);
        } catch (UnsupportedEncodingException ex) {
            return "";
        }
    }

    public static String decrypt64_orEmpty(CharSequence inputBase64) {
        if (inputBase64 == null || inputBase64.toString().isEmpty()) {
            return "";
        }
        return decrypt64_orEmpty(TGS_ByteArrayUtils.toByteArray(inputBase64));
    }

    private static byte[] keyBytes3DES(CharSequence key) {
        var keyString = key.toString();
        while (TGS_ByteArrayUtils.toByteArray(keyString).length > 24) {
            keyString = keyString.substring(1, keyString.length() - 1);
        }
        return TGS_ByteArrayUtils.toByteArray(keyString);
    }

    public static String encrypt3DES_orEmpty(CharSequence key, CharSequence originalValue) {
        var cipher = new TripleDesCipher();
        cipher.setKey(keyBytes3DES(key));
        try {
            return cipher.encrypt(originalValue.toString());
        } catch (DataLengthException | IllegalStateException | InvalidCipherTextException ex) {
            return "";
        }
    }

    public static String decrypt3DES_orEmpty(CharSequence key, CharSequence encryptedValue) {
        var cipher = new TripleDesCipher();
        cipher.setKey(keyBytes3DES(key));
        try {
            return cipher.decrypt(encryptedValue.toString());
        } catch (DataLengthException | IllegalStateException | InvalidCipherTextException ex) {
            return "";
        }
    }

    public static String shift(CharSequence cs) {
        var s = cs.toString();
        return s.charAt(s.length() - 1) + s.substring(0, s.length() - 1);
    }

    public static String shift(CharSequence cs, int shiftCount) {
        var s = cs.toString();
        for (var i = 0; i < shiftCount; i++) {
            s = shift(s);
        }
        return s;
    }
}
