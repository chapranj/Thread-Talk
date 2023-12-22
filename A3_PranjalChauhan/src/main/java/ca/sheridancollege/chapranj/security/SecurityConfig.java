package ca.sheridancollege.chapranj.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Autowired
	DataSource dataSource;

	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Autowired
	public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(passwordEncoder());
	}

	@Bean
	JdbcUserDetailsManager jdbcUserDetailsManager() {
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager();
		jdbcUserDetailsManager.setDataSource(dataSource);
		return jdbcUserDetailsManager;
	}

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).disable())
				.headers(headers -> headers.frameOptions(FrameOptionsConfig::disable))
				.authorizeHttpRequests((authz) -> {
					authz.requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll()
							.requestMatchers(AntPathRequestMatcher.antMatcher("/register/**")).hasAnyRole("MANAGER")
							.requestMatchers(AntPathRequestMatcher.antMatcher("view/**")).hasAnyRole("USER", "MANAGER")
							.requestMatchers(AntPathRequestMatcher.antMatcher("viewAdmin/**")).hasAnyRole("MANAGER")
							.requestMatchers(AntPathRequestMatcher.antMatcher("manageThreads/**")).hasAnyRole("MANAGER")
							.requestMatchers(AntPathRequestMatcher.antMatcher("startThread/**"))
							.hasAnyRole("MANAGER", "USER").requestMatchers(AntPathRequestMatcher.antMatcher("/"))
							.permitAll().anyRequest().authenticated();
				}).formLogin((login) -> login.loginPage("/login").permitAll())

				.logout((logout) -> logout.logoutUrl("/logout").logoutSuccessUrl("/?msg=logout is successful")
						.clearAuthentication(true).invalidateHttpSession(true).deleteCookies("JSESSIONID"))
				.exceptionHandling((exception) -> exception.accessDeniedPage("/access-denied"));
//				.accessDeniedHandler(accessDeniedHandler));
		return http.build();
	}

}
