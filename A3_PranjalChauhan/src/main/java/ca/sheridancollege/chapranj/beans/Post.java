package ca.sheridancollege.chapranj.beans;

import java.sql.Timestamp;

import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Component
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Post {
	private int postId;
	private String content;
	private String username;
	private Timestamp date;
	private int threadId;
}
