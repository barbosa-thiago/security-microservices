package com.thiago.valhallaproject;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@SpringBootApplication
@EnableEurekaClient
public class ValhallaApplication {

    public static void main(String[] args) {
        SpringApplication.run(ValhallaApplication.class, args);
    }

}
