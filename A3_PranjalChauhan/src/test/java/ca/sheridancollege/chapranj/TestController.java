package ca.sheridancollege.chapranj;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
public class TestController {
			
	@Autowired
	private MockMvc mockMvc;

	@Test
	public void testroot() throws Exception {
		this.mockMvc.perform(get("/")).andExpect(status().isOk()).andExpect(view().name("threads"));
	}

	@Test
	public void testPosts() throws Exception {
		this.mockMvc.perform(get("/posts")).andExpect(status().isFound());
	}

	@Test
	public void testLogin() throws Exception {
		this.mockMvc.perform(get("/login")).andExpect(status().isOk()).andExpect(view().name("login"));
	}

	@Test
	public void testStartThread() throws Exception {
		this.mockMvc.perform(get("/startThread")).andExpect(status().isFound());
	}

	@Test
	public void testRegister() throws Exception {
		this.mockMvc.perform(get("/register")).andExpect(status().isFound());
	}

	@Test
	public void testAddPost() throws Exception {
		this.mockMvc.perform(post("/addPost")).andExpect(status().isFound());
	}
	
	@Test
	public void testAddThread() throws Exception {
		this.mockMvc.perform(post("/addThread")).andExpect(status().isFound());
	}
	
	
	
	
	
}
