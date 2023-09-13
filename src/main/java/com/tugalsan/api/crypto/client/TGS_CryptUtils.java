package com.tugalsan.api.crypto.client;

import com.googlecode.gwt.crypto.bouncycastle.util.encoders.Base64;
import com.googlecode.gwt.crypto.client.TripleDesCipher;
import com.tugalsan.api.bytes.client.TGS_ByteArrayUtils;
import com.tugalsan.api.charset.client.*;
import com.tugalsan.api.unsafe.client.*;

public class TGS_CryptUtils {

    public static String encrypt64(byte[] bytes) {
        return TGS_UnSafe.call(() -> {
            if (bytes == null) {
                return "";
            }
            return new String(Base64.encode(bytes), TGS_CharSetUTF8.UTF8);
        }, e -> "");
    }

    public static String encrypt64(CharSequence inputString) {
        return TGS_UnSafe.call(() -> {
            if (inputString == null || inputString.toString().isEmpty()) {
                return "";
            }
            return encrypt64(TGS_ByteArrayUtils.toByteArray(inputString));
        }, e -> "");
    }

    public static String decrypt64(byte[] bytes) {
        return TGS_UnSafe.call(() -> {
            if (bytes == null) {
                return "";
            }
            return new String(Base64.decode(bytes), TGS_CharSetUTF8.UTF8);
        }, e -> "");
    }

    public static String decrypt64(CharSequence inputBase64) {
        return TGS_UnSafe.call(() -> {
            if (inputBase64 == null || inputBase64.toString().isEmpty()) {
                return "";
            }
            return decrypt64(TGS_ByteArrayUtils.toByteArray(inputBase64));
        }, e -> "");
    }

    private static byte[] keyBytes3DES(CharSequence key) {
        var keyString = key.toString();
        while (TGS_ByteArrayUtils.toByteArray(keyString).length > 24) {
            keyString = keyString.substring(1, keyString.length() - 1);
        }
        return TGS_ByteArrayUtils.toByteArray(keyString);
    }

    public static String encrypt3DES(CharSequence key, CharSequence originalValue) {
        return TGS_UnSafe.call(() -> {
            var cipher = new TripleDesCipher();
            cipher.setKey(keyBytes3DES(key));
            return cipher.encrypt(originalValue.toString());
        });
    }

    public static String decrypt3DES(CharSequence key, CharSequence encryptedValue) {
        return TGS_UnSafe.call(() -> {
            var cipher = new TripleDesCipher();
            cipher.setKey(keyBytes3DES(key));
            return cipher.decrypt(encryptedValue.toString());
        });
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
