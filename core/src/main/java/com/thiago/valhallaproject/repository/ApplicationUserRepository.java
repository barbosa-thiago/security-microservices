package com.thiago.valhallaproject.repository;

import com.thiago.valhallaproject.domain.ApplicationUser;
import com.thiago.valhallaproject.domain.GodName;
import org.springframework.data.repository.PagingAndSortingRepository;


public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {
    ApplicationUser findByUsername(String username);

}
