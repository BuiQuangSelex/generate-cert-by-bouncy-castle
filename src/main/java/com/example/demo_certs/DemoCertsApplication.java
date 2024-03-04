package com.example.demo_certs;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

@SpringBootApplication
public class DemoCertsApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoCertsApplication.class, args);
    }

}
