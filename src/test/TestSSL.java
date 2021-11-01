package test;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.conn.util.PublicSuffixMatcherLoader;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import java.util.stream.Collectors;

public class TestSSL {

    private static final String PKCS12 = "PKCS12";
    private static String rhapsodyRPIWSUrl = "https://secure-rpiws.rhapsody.com/rpiws/version";
    
    public static void main(String[] args) {
        try {
            String ksFile = "private.p12";
            String ksPassword = "password";
            String tsFile = "trustStore";
            String tsPassword = "password";
            String tlsVerion = "TLSv1.2";
            //Both Keystore and TrustStore, apache httpclient
            SSLConnectionSocketFactory sslConSocFactory = initSSLFactory(ksFile, ksPassword, tsFile,
                    tsPassword, tlsVerion);
            callRPIWS(sslConSocFactory);
            
            //Keystore only java
            SSLSocketFactory sslFactory = createSSLFactory(ksFile, ksPassword,tlsVerion);
            callRPIWS(sslFactory);

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void callRPIWS(SSLConnectionSocketFactory sslConSocFactory)
            throws IOException, ClientProtocolException {
        CloseableHttpClient httpclient = HttpClients.custom()
                .setSSLSocketFactory(sslConSocFactory).build();

        HttpGet httpget = new HttpGet(rhapsodyRPIWSUrl);
        CloseableHttpResponse httpresponse = httpclient.execute(httpget);

        String result = new BufferedReader(
                new InputStreamReader(httpresponse.getEntity().getContent())).lines()
                        .collect(Collectors.joining("\n"));
        System.out.println(result);
    }
    
    private static void callRPIWS(SSLSocketFactory sslsocketfactory)
            throws IOException, ClientProtocolException {
        URL url = new URL(rhapsodyRPIWSUrl);
        HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();
        conn.setSSLSocketFactory(sslsocketfactory);
        InputStream inputstream = conn.getInputStream();

        
        String result = new BufferedReader(
                new InputStreamReader(inputstream)).lines()
                        .collect(Collectors.joining("\n"));
        System.out.println(result);
    }

    /*
     *   Apache Httpclient Init
     */
    private static SSLConnectionSocketFactory initSSLFactory(String ksFile, String ksPassword,
            String tsFile, String tsPassword, String tlsVerion) throws KeyStoreException,
            FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException,
            KeyManagementException, UnrecoverableKeyException, MalformedURLException {
        KeyStore keyStore = initKeyStore(ksFile, ksPassword);
        SSLContextBuilder builder = new SSLContextBuilder();
        SSLContext sslContext = builder.loadTrustMaterial(new URL(tsFile), tsPassword.toCharArray())
                .setProtocol(tlsVerion).loadKeyMaterial(keyStore, ksPassword.toCharArray()).build();
        HostnameVerifier hv = new DefaultHostnameVerifier(PublicSuffixMatcherLoader.getDefault());

        SSLConnectionSocketFactory sslConSocFactory = new SSLConnectionSocketFactory(sslContext,
                new String[] { tlsVerion }, null, hv);
        return sslConSocFactory;
    }

    private static KeyStore initKeyStore(String ksFile, String ksPassword) throws KeyStoreException,
            FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        FileInputStream fis = new FileInputStream(ksFile);
        keyStore.load(fis, ksPassword.toCharArray()); // There are other ways to read the password.
        fis.close();
        return keyStore;
    }
    
    /*
     * Pure Java runtime Init  SSL Context
     * Setup  SSLContext
     */

    private static SSLContext sslContext(String keystoreFile, String password)
            throws GeneralSecurityException, IOException {

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (InputStream in = new FileInputStream(keystoreFile)) {
            keystore.load(in, password.toCharArray());
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory
                .getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keystore, password.toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keystore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(),
                new SecureRandom());

        return sslContext;
    }

    /*
     * Setup private key  only
     * setup SSLSocketFactory
     */
    private static SSLSocketFactory createSSLFactory(String keystoreFile, String keystorePassword, 
                            String tlsVersion) {
        KeyStore keyStore = null;
        SSLContext ctx = null;

        try {
            keyStore = initKeyStore(keystoreFile, keystorePassword);
            
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keystorePassword.toCharArray());
            
            ctx = SSLContext.getInstance(tlsVersion);
            ctx.init(kmf.getKeyManagers(), null, null);
           
            javax.net.ssl.SSLSocketFactory factory = ctx.getSocketFactory();
            return factory;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
