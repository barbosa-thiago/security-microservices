package com.thiago.valhallaproject.domain;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotEmpty;

@Getter
@Setter
@Builder
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor
@AllArgsConstructor
@Entity
public class ApplicationUser {
    public ApplicationUser(ApplicationUser applicationUser){
        this.id = applicationUser.getId();
        this.username = applicationUser.getUsername();
        this.password = applicationUser.getPassword();
        this.role = applicationUser.getRole();
    }

    //    Odin, Frigg, Thor, Loki, Balder, Hod, Heimdall and Tyr
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    @NotEmpty(message = "must have a username")
    @Column(nullable = false)
    private String username;
    @NotEmpty(message = "must have a password")
    @Column(nullable = false)
    private String password;
    @NotEmpty()
    @Column(nullable = false)
    private String role = "USER";
}
