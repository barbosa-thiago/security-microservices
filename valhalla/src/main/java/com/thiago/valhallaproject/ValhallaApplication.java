package com.thiago.valhallaproject;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EntityScan({"com.thiago.valhallaproject.domain"})
@EnableJpaRepositories({"com.thiago.valhallaproject.repository"})
public class ValhallaApplication {

    public static void main(String[] args) {
        SpringApplication.run(ValhallaApplication.class, args);
    }

}
