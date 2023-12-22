package ca.sheridancollege.chapranj.beans;

import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Component
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Thread {
	private int threadId;
	private String title;
	private String username;
}
