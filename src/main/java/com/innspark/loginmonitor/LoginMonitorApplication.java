package com.innspark.loginmonitor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class LoginMonitorApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginMonitorApplication.class, args);
    }
}
