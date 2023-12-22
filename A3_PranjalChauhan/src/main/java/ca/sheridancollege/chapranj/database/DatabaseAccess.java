package ca.sheridancollege.chapranj.database;

import java.util.ArrayList;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import ca.sheridancollege.chapranj.beans.Post;
import ca.sheridancollege.chapranj.beans.Thread;

@Repository
public class DatabaseAccess {
	@Autowired
	protected NamedParameterJdbcTemplate jdbc;

	public ArrayList<Post> selectAllFromPosts() {
		String queryString = "select * from posts";
		ArrayList<Post> posts = (ArrayList<Post>) jdbc.query(queryString, new BeanPropertyRowMapper<Post>(Post.class));
		return posts;
	}

	public ArrayList<Thread> selectAllFromThreads() {
		String queryString = "select * from threads";

		ArrayList<Thread> threads = (ArrayList<Thread>) jdbc.query(queryString,
				new BeanPropertyRowMapper<Thread>(Thread.class));
		System.out.println("All threads: " + threads);
		return threads;
	}

	public ArrayList<Post> selectPostsByThread(int threadId) {
		MapSqlParameterSource namedParameters = new MapSqlParameterSource();
		namedParameters.addValue("threadId", threadId);
		String queryString = "select * from posts where threadId = :threadId";
		ArrayList<Post> posts = (ArrayList<Post>) jdbc.query(queryString, namedParameters,
				new BeanPropertyRowMapper<Post>(Post.class));
		System.out.println("Posts by ThreadId: " + posts);
		return posts;
	}

	public String getThreadName(int threadId) {
		MapSqlParameterSource namedParameters = new MapSqlParameterSource();
		System.out.println("Thread Id in getThreadName: " + threadId);
		namedParameters.addValue("threadId", threadId);
		String queryString = "select title from threads where threadId = :threadId";
		List<String> titles = jdbc.queryForList(queryString, namedParameters, String.class);

		if (!titles.isEmpty()) {
			return titles.get(0);
		} else {
			// Handle the case where no thread with the given ID was found.
			return null; // or throw an exception, or handle it in a way that makes sense for your
							// application
		}
	}

	public int insertIntoPosts(Post post) {
		MapSqlParameterSource namedParameters = new MapSqlParameterSource();
		namedParameters.addValue("content", post.getContent());
		namedParameters.addValue("username", post.getUsername());
		namedParameters.addValue("threadId", post.getThreadId());
		String qString = "INSERT INTO posts (content, threadId, username) VALUES (:content, :threadId, :username)";
		int res = jdbc.update(qString, namedParameters);
		return res;
	}

	public int delete(int id) {
		MapSqlParameterSource namedParameters = new MapSqlParameterSource();
		namedParameters.addValue("id", id);
		String qString = "delete from posts where postId = :id";
		int res = jdbc.update(qString, namedParameters);
		return res;
	}

	public int insertIntoThreads(Thread thread) {
		MapSqlParameterSource namedParameters = new MapSqlParameterSource();
		namedParameters.addValue("title", thread.getTitle());
		namedParameters.addValue("username", thread.getUsername());
		String qString = "INSERT INTO threads (title, username) VALUES (:title, :username)";
		int res = jdbc.update(qString, namedParameters);
		return res;
	}

	public int deleteThread(int threadId) {
		MapSqlParameterSource namedParameters = new MapSqlParameterSource();
		namedParameters.addValue("threadId", threadId);
		String qString = "delete from threads where threadId = :threadId";
		int res = jdbc.update(qString, namedParameters);
		return res;
	}

}
