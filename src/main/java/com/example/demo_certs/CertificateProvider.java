package com.example.demo_certs;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

@Service
public class CertificateProvider {

    private static final String BC_PROVIDER = "BC";

    private static final String KEY_ALGORITHM = "RSA";

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private static final String KEY_STORE_PATH = "ca-keystore.p12";

    private static final String KEY_STORE_TYPE = "PKCS12";

    private static final String KEY_STORE_PASS = "123456";

    private KeyPairGenerator keyPairGenerator;

    @PostConstruct
    void init() throws Exception {
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());
        keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);

        var keyStore = loadKeyStore(KEY_STORE_PATH, KEY_STORE_PASS);
        X509Certificate rootCaCertificate = (X509Certificate) keyStore.getCertificate("ca-certificate");
        PrivateKey rootCaPrivateKey = (PrivateKey) keyStore.getKey("ca-certificate", "".toCharArray());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 10);
        Date endDate = calendar.getTime();

        var clientCertificate = generateClientCertSignedByRootCert("CN=client-cert", keyPair, rootCaPrivateKey, rootCaCertificate, startDate, endDate);
        System.out.println(clientCertificate);
        System.out.println(keyPair.getPrivate());

        showCert(clientCertificate);
        showPrivateKey(keyPair.getPrivate());
        writeCertToFileBase64Encoded(clientCertificate, "client-certificate.pem");
        writePrivateKeyToFileBase64Encoded(keyPair.getPrivate(), "client-private-key.pem");
    }

    public KeyStore loadKeyStore(String path, String pass) throws KeyStoreException, NoSuchProviderException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
        keyStore.load(new FileInputStream(path), pass.toCharArray());
        return keyStore;
    }

    private void generateRootCert() throws Exception {

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Issued By and Issued To same for root certificate
        X500Name rootCertIssuer = new X500Name("CN=root-ca");
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);

        writeCertToFileBase64Encoded(rootCert, "root-cert.cer");
        exportKeyPairToKeystoreFile(rootKeyPair, rootCert, "root-cert", "root-cert.pfx", KEY_STORE_TYPE, KEY_STORE_PASS);
    }

    /**
     * tạo chứng chỉ x509 cho client và ký bằng root CA
     * */
    public X509Certificate generateClientCertSignedByRootCert(String subj,
                                                              KeyPair keyPair,
                                                              PrivateKey caPrivateKey,
                                                              X509Certificate caCertificate,
                                                              Date startDate, Date enddate) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException {
        X500Name rootCertIssuer = new JcaX509CertificateHolder(caCertificate).getSubject();
        X500Name issuedCertSubject = new X500Name(subj);
        BigInteger clientCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Sign the new KeyPair with the root cert Private Key
        PKCS10CertificationRequestBuilder certificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, keyPair.getPublic());

        // Sign the new KeyPair with the root cert Private Key
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
        ContentSigner contentSigner = signerBuilder.build(caPrivateKey);

        var csr = certificationRequestBuilder.build(contentSigner);

        // Use the Signed KeyPair and CSR to generate an issued Certificate
        // Here serial number is randomly generated. In general, CAs use
        // a sequence to generate Serial number and avoid collisions
        X509v3CertificateBuilder clientCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, clientCertSerialNum, startDate, enddate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
        clientCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        // Add Issuer cert identifier as Extension
        clientCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(caCertificate));
        clientCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        X509CertificateHolder clientCertHolder = clientCertBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(clientCertHolder);
    }

    public static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws IOException, CertificateEncodingException {
        try (FileOutputStream certificateOut = new FileOutputStream(fileName)) {
            certificateOut.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            char[] charArray = new String(Base64.encode(certificate.getEncoded()), StandardCharsets.UTF_8).toCharArray();
            int i = 0;
            int index = 0;
            while (i < 65 && index < charArray.length) {
                certificateOut.write(charArray[index]);
                i++;
                index++;
                if (i == 65 || index == charArray.length) {
                    certificateOut.write("\n".getBytes(StandardCharsets.UTF_8));
                    i = 0;
                }
            }
            certificateOut.write("-----END CERTIFICATE-----".getBytes());
        }
    }

    public static void writePrivateKeyToFileBase64Encoded(PrivateKey privateKey, String fileName) throws IOException {
        try (FileOutputStream privateKeyOut = new FileOutputStream(fileName)) {
            privateKeyOut.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
            char[] charArray = new String(Base64.encode(privateKey.getEncoded()), StandardCharsets.UTF_8).toCharArray();
            int i = 0;
            int index = 0;
            while (i < 65 && index < charArray.length) {
                privateKeyOut.write(charArray[index]);
                i++;
                index++;
                if (i == 65 || index == charArray.length) {
                    privateKeyOut.write("\n".getBytes(StandardCharsets.UTF_8));
                    i = 0;
                }
            }
            privateKeyOut.write("-----END PRIVATE KEY-----".getBytes());
        }
    }

    public static void exportKeyPairToKeystoreFile(KeyPair keyPair, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }

    public void showPrivateKey(PrivateKey privateKey) {
        System.out.println("\n-----BEGIN PRIVATE KEY-----");
        showCertToFileBase64Encoded(Base64.encode(privateKey.getEncoded()));
        System.out.println("-----END PRIVATE KEY-----\n");
    }

    public void showCert(Certificate certificate) throws CertificateEncodingException {
        System.out.println("\n-----BEGIN CERTIFICATE-----");
        showCertToFileBase64Encoded(Base64.encode(certificate.getEncoded()));
        System.out.println("-----END CERTIFICATE-----\n");
    }

    public void showCertToFileBase64Encoded(byte[] base64Cert) {
        char[] charArray = new String(base64Cert, StandardCharsets.UTF_8).toCharArray();
        int i = 0;
        int index = 0;
        while (i < 65 && index < charArray.length) {
            System.out.print(charArray[index]);
            i++;
            index++;
            if (i == 65 || index == charArray.length) {
                System.out.println();
                i = 0;
            }
        }
    }

}
