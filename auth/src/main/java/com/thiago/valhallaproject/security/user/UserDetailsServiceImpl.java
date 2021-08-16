package com.thiago.valhallaproject.security.user;

import com.thiago.valhallaproject.domain.ApplicationUser;
import com.thiago.valhallaproject.repository.ApplicationUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.Collection;

@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    private final ApplicationUserRepository applicationUserRepository;
    @Override
    public UserDetails loadUserByUsername(String username) {
        log.info("searching in the database the user by username {}", username);
        ApplicationUser applicationUser = applicationUserRepository.findByUsername(username);
        log.info("ApplicationUser found {}", applicationUser);
        if(applicationUser == null){
            throw new UsernameNotFoundException(String.format("User %s not found", username));
        }
        return new CustomUserDetails(applicationUser);
    }

    public static final class CustomUserDetails  extends ApplicationUser implements UserDetails{


        public CustomUserDetails(ApplicationUser applicationUser) {
            super(applicationUser);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_" + this.getRole());
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
