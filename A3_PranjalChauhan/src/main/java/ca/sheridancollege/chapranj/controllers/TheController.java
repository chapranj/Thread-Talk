package ca.sheridancollege.chapranj.controllers;

import java.util.ArrayList;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import ca.sheridancollege.chapranj.beans.Post;
import ca.sheridancollege.chapranj.beans.Thread;
import ca.sheridancollege.chapranj.beans.UserRegistration;
import ca.sheridancollege.chapranj.database.DatabaseAccess;

@Controller
public class TheController {
	// the root page is the one that shows all the threads, but in order to view
	// posts in a single thread or post in it,
	// you must be either a user or a manager.
	// The user can view posts create posts, start a new thread.
	// The manager can remove posts as well.
	// The manager is the one having privileges to register new users. It is assumed
	// that once the new user is registered by the manager,
	// the password of the new user is set by the manager, then the user is mailed
	// to change his/her password in order to
	// be secure.

	
	// This application has the following users:
	// username-chapranj & password-password & privileges-user
	// username-nikolai & password-password & privileges-manager
	// please consider using the above details for doing operations with the
	// application.
	
	//The features that are available for the managers will only be visible when the manager is logged in
	//for example the button for register new user will only be visible when the manager is logged in
	

	@Autowired
	JdbcUserDetailsManager jdbcUserDetailsManager;

	@Autowired
	private DatabaseAccess da;

	@GetMapping("/posts")
	public String getIndex(Model model) {
		model.addAttribute("posts", da.selectAllFromPosts());
		model.addAttribute("post", new Post());
		return "posts";
	}

	@GetMapping("/")
	public String getThreads(Model model) {
		model.addAttribute("thread", new Thread());
		model.addAttribute("threads", da.selectAllFromThreads());
		System.out.println(da.selectAllFromThreads());
		return "threads";
	}

	@GetMapping("/login")
	public String getLogin() {
		return "login";
	}
	
	//I have added the below method in such a way that when the user is logged in and he clicks the view thread, then he should be served with the posts.html page which doesnt have the delete options
	// and if the manager logs in, then the viewAdmin.html page will be served which has the delete options.


	@GetMapping("/view/{threadId}")
	public String getPostByThread(Model model, @PathVariable int threadId, Authentication authentication) {
		for (GrantedAuthority auth : authentication.getAuthorities()) {
			if ("ROLE_USER".equals(auth.getAuthority())) {
				model.addAttribute("posts", da.selectPostsByThread(threadId));
				model.addAttribute("title", da.getThreadName(threadId));
				model.addAttribute("threadId", threadId);
				model.addAttribute("post", new Post());
				System.out.println("Thread id in getPostByThread: " + threadId);
				return "posts";

			} else if ("ROLE_MANAGER".equals(auth.getAuthority())) {
				System.out.println("manager detected");
				model.addAttribute("posts", da.selectPostsByThread(threadId));
				model.addAttribute("title", da.getThreadName(threadId));
				model.addAttribute("threadId", threadId);
				model.addAttribute("post", new Post());
				System.out.println("Thread id in getPostByThread: " + threadId);
				return "viewAdmin";
			}
		}
		return "posts";

	}

	@PostMapping("/addPost")
	public String addPost(Model model, @ModelAttribute Post post, @RequestParam int threadId,
			Authentication authentication) {
		post.setThreadId(threadId);
		System.out.println("Thread Id in /addPost: " + threadId);
		int res = da.insertIntoPosts(post);
		System.out.println(res);
		model.addAttribute("post", new Post());
		model.addAttribute("posts", da.selectPostsByThread(threadId));
		return "redirect:/view/" + threadId;

	}

	@GetMapping("/startThread")
	public String getStartThread(Model model) {
		model.addAttribute("thread", new Thread());
		return "startThread";
	}

	@PostMapping("/addThread")
	public String addThread(Model model, @ModelAttribute Thread thread) {
		int res = da.insertIntoThreads(thread);
		System.out.println(res);
		model.addAttribute("thread", new Thread());
		return "redirect:/";
	}

	@GetMapping("/viewAdmin")
	public String getAdminPage() {
		return "viewAdmin";
	}

	@GetMapping("/delete/{postId}")
	public String deleter(@PathVariable int postId, Model model, @RequestParam int threadId) {
		int res = da.delete(postId);
		System.out.println(res);
		return "redirect:/view/" + threadId;
	}

	@GetMapping("/register")
	public String register(Model model, UserRegistration user) {
		model.addAttribute("user", user);
		return "register";
	}
	

	@PostMapping("/register")
	public String processRegister(@ModelAttribute UserRegistration user) {
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		if (user.getAuthority().equalsIgnoreCase("user")) {
			authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		} else if (user.getAuthority().equalsIgnoreCase("manager")) {
			authorities.add(new SimpleGrantedAuthority("ROLE_MANAGER"));
		} else {
			authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
			authorities.add(new SimpleGrantedAuthority("ROLE_MANAGER"));
		}
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String encodedPassword = passwordEncoder.encode(user.getPassword());
		User newuser = new User(user.getUsername(), encodedPassword, authorities);
		jdbcUserDetailsManager.createUser(newuser);
		return "redirect:/";
	}

	@GetMapping("/manageThreads")
	public String getManageThreads(Model model) {
		model.addAttribute("threads", da.selectAllFromThreads());
		return "manageThreads";
	}

	@GetMapping("/deleteThread/{threadId}")
	public String threadDeleter(@PathVariable int threadId, Model model) {
		int res = da.deleteThread(threadId);
		System.out.println(res);
		return "redirect:/";
	}

	@GetMapping("/access-denied")
	public String accessDenied() {
		return "access-denied";
	}

}
