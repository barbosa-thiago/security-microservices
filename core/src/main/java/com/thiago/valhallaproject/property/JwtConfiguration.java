package com.thiago.valhallaproject.property;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("jwt.config")
@Setter
@Getter
@ToString
public class JwtConfiguration {
    private String loginUrl = "/login";
    private Header header = new Header();
    private int expiration = 3600;
    private String privateKey = "NTdkYwBTGG1h0uv8nqc4DCwjU3SuuV72";
    private String type = "encripted";

    @Getter
    @Setter
    public static class Header{
        private String name = "Authorization";
        private String prefix = "Bearer ";
    }
}
