package package com.seecode.auth;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import cn.com.autohome.pop.domain.exception.CipherException;


public class CipherHelper {
    private static final byte[] IV = { 0, 0, 0, 0, 0, 0, 0, 0 };
    private static final Log log = LogFactory.getLog(CipherHelper.class);
    public static String md5Base64(String src){
        if (src == null) {
            log.error("source string isn't nullable");
            throw new NullPointerException("source string isn't nullable");
        }
        byte[] resultByte = DigestUtils.md5(src);
        return Base64.encodeBase64String(resultByte);
    }
    public static String sha1Base64(String src){
        if (src == null) {
            log.error("source string isn't nullable");
            throw new NullPointerException("source string isn't nullable");
        }
        return Base64.encodeBase64String(DigestUtils.sha(src));
    }
    public static byte[] DESEncrypt(byte[] src, byte[] key)
            throws CipherException {
        byte[] result = null;
        try {
            SecretKeySpec dks = new SecretKeySpec(key, "DESede");
            IvParameterSpec ips = new IvParameterSpec(IV);
            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cert, cwe, owasp-a6, sans-top25-porous
            cipher.init(Cipher.ENCRYPT_MODE, dks, ips);
            result = cipher.doFinal(src);
        } catch (InvalidKeyException ex) {
            log.error("Invalid Key", ex);
            throw new CipherException("Invalid Key", ex);
        } catch (NoSuchAlgorithmException ex) {
            log.error("No such a DES Algorithm", ex);
            throw new CipherException("No such a DES Algorithm", ex);
        } catch (NoSuchPaddingException ex) {
            log.error("No such a DES Padding", ex);
            throw new CipherException(ex.getMessage());
        } catch (BadPaddingException ex) {
            log.error("The padding is bad", ex);
            throw new CipherException(ex.getMessage());
        } catch (IllegalBlockSizeException ex) {
            log.error("Illegal block size", ex);
            throw new CipherException(ex.getMessage());
        } catch (IllegalStateException ex) {
            log.error("Illegal State", ex);
            throw new CipherException(ex.getMessage());
        } catch (InvalidAlgorithmParameterException ex) {
            log.error("The Algorithm Parameter is invalid", ex);
            throw new CipherException(ex.getMessage());
        }
        return result;
    }
    public static byte[] DESDecrypt(byte[] src, byte[] key)
            throws CipherException {
        byte[] result = null;
        try {
            SecretKeySpec dks = new SecretKeySpec(key, "DESede");
            IvParameterSpec ips = new IvParameterSpec(IV);
            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, dks, ips);
            result = cipher.doFinal(src);
        } catch (InvalidKeyException ex) {
            log.error("Invalid Key", ex);
            throw new CipherException("Invalid Key", ex);
        } catch (NoSuchAlgorithmException ex) {
            log.error("No such a DES Algorithm", ex);
            throw new CipherException("No such a DES Algorithm", ex);
        } catch (NoSuchPaddingException ex) {
            log.error("No such a DES Padding", ex);
            throw new CipherException(ex.getMessage());
        } catch (BadPaddingException ex) {
            log.error("The padding is bad", ex);
            throw new CipherException(ex.getMessage());
        } catch (IllegalBlockSizeException ex) {
            log.error("Illegal block size", ex);
            throw new CipherException(ex.getMessage());
        } catch (IllegalStateException ex) {
            log.error("Illegal State", ex);
            throw new CipherException(ex.getMessage());
        } catch (InvalidAlgorithmParameterException ex) {
            log.error("The Algorithm Parameter is invalid", ex);
            throw new CipherException(ex.getMessage());
        }
        return result;
    }
    public static String DESEncryptBase64(String src, String key)
            throws CipherException {
        if (src == null || key == null) {
            log.error("source or key string isn't nullable");
            throw new NullPointerException(
                    "source or key string isn't nullable");
        }
        String result = null;
        try {
            byte[] srcBytes = src.getBytes("UTF-8");
            byte[] keyBytes = Base64.decodeBase64(key);
            byte[] cipherBytes = DESEncrypt(srcBytes, keyBytes);
            result = Base64.encodeBase64String(cipherBytes);
        } catch (IllegalStateException ex) {
            log.error("Illegal State", ex);
            throw new CipherException(ex.getMessage());
        } catch (IOException ex) {
            log.error("I/O Error", ex);
            throw new CipherException(ex.getMessage());
        }
        return result;
    }
    public static String DESDecryptBase64(String src, String key)
            throws CipherException {
        if (src == null || key == null) {
            log.error("source or key string isn't nullable");
            throw new NullPointerException(
                    "source or key string isn't nullable");
        }
        String result = null;
        try {
            byte[] srcBytes = Base64.decodeBase64(src);
            byte[] keyBytes = Base64.decodeBase64(key);
            result = new String(DESDecrypt(srcBytes, keyBytes), "UTF-8");
        } catch (IllegalStateException ex) {
            log.error("Illegal State", ex);
            throw new CipherException(ex.getMessage());
        } catch (IOException ex) {
            log.error("I/O Error", ex);
            throw new CipherException(ex.getMessage());
        }
        return result;
    }


    /**
     * doBase64Encoding
     *
     * @param src
     *            String
     * @return String
     * @throws CipherException
     */
    public static String doBase64Encoding(String src) throws CipherException {
        if (src == null) {
            log.error("source string isn't nullable");
            throw new NullPointerException(
                    "source string isn't nullable");
        }
        String result = null;
        try {
            result = Base64.encodeBase64String(src.getBytes("UTF8"));
        } catch (UnsupportedEncodingException ex) {
            log.error("No such a encoding Error", ex);
            throw new CipherException("No such a encoding Error", ex);
        }
        return result;
    }
    /**
     * doBase64Decoding
     *
     * @return String
     * @throws CipherException
     */
    public static String doBase64Decoding(String src) throws CipherException {
        if (src == null) {
            log.error("source string isn't nullable");
            throw new NullPointerException(
                    "source string isn't nullable");
        }
        try {
            return new String(Base64.decodeBase64(src), "UTF8");
        } catch (UnsupportedEncodingException ex) {
            log.error("No such a encoding Error", ex);
            throw new CipherException("No such a encoding Error", ex);
        }catch (IOException ex) {
            log.error("I/O Error", ex);
            throw new CipherException(ex.getMessage());
        }
    }
    public static String DESEncryptHex(String src, String key)
            throws CipherException {
        String result = null;
        if (src == null || key == null) {
            log.error("source or key string isn't nullable");
            throw new NullPointerException(
                    "source or key string isn't nullable");
        }
        try {
            byte[] srcBytes = src.getBytes("UTF-8");
            byte[] keyBytes = Hex.decodeHex(key.toCharArray());
            result = new String(Hex.encodeHex(DESEncrypt(srcBytes, keyBytes)));
        } catch (IllegalStateException ex) {
            log.error("Illegal State", ex);
            throw new CipherException(ex.getMessage());
        } catch (DecoderException ex) {
            log.error("source or key is invalid hex encoding", ex);
            throw new CipherException("source or key is invalid hex encoding", ex);
        } catch (UnsupportedEncodingException ex) {
            log.error("No such a encoding Error", ex);
            throw new CipherException("No such a encoding Error", ex);
        }
        return result;
    }
    public static String DESDecryptHex(String src, String key)
            throws CipherException {
        if (src == null || key == null) {
            log.error("source or key string isn't nullable");
            throw new NullPointerException(
                    "source or key string isn't nullable");
        }
        String result = null;
        try {
            byte[] keyBytes = Hex.decodeHex(key.toCharArray());
            byte[] srcBytes = Hex.decodeHex(src.toCharArray());
            result = new String(DESDecrypt(srcBytes, keyBytes), "UTF-8");
        } catch (IllegalStateException ex) {
            log.error("Illegal State", ex);
            throw new CipherException(ex.getMessage());
        }catch (IOException ex) {
            log.error("I/O Error", ex);
            throw new CipherException(ex.getMessage());
        } catch (DecoderException ex) {
            log.error("source or key is invalid hex encoding", ex);
            throw new CipherException("source or key is invalid hex encoding", ex);
        }
        return result;
    }
}