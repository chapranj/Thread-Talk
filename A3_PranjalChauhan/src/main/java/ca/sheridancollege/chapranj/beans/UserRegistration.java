package ca.sheridancollege.chapranj.beans;

import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Component
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRegistration {

	private String username;
	private String password;
	private String email;
	private String authority="user";
}
