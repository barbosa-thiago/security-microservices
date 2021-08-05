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
public class GodName {
    //    Odin, Frigg, Thor, Loki, Balder, Hod, Heimdall and Tyr
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    @NotEmpty(message = "must have a name")
    @Column(nullable = false)
    private String name;
}
