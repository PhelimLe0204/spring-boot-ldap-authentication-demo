package com.concretepage;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class HomeController {
	@GetMapping("/login")
	public ModelAndView login() {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("custom-login");
		return mav;
	}

	@GetMapping("/secure/man")
	public ModelAndView welcome1(Authentication authentication) {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("info");
		return mav;
	}

	@GetMapping("/secure/dev")
	public ModelAndView welcome2(Authentication authentication) {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("info");
		return mav;
	}

	@GetMapping("/accessDenied")
	public ModelAndView error() {
		ModelAndView mav = new ModelAndView();
		String errorMessage = "You are not authorized to access this page.";
		mav.addObject("errorMsg", errorMessage);
		mav.setViewName("access-denied");
		return mav;
	}
}
