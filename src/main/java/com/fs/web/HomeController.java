package com.fs.web;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.thymeleaf.util.StringUtils;

@Controller
public class HomeController {

	private final Logger logger = Logger.getLogger(HomeController.class);

	@RequestMapping({ "/", "/index" })
	public String index() {
		return "index";
	}

	@RequestMapping("/loginindex")
	public String loginindex() {
		return "login";
	}

	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public String login(HttpServletRequest request, @RequestParam(value = "username", required = false) String username,
			@RequestParam(value = "password", required = false) String password, RedirectAttributes redirectAttributes)
			throws Exception {
		System.out.println("HomeController.login()");
		if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
			logger.info("用户名或密码为空! ");
			redirectAttributes.addFlashAttribute("message", "用户名或密码为空!");
			return "redirect:loginindex";
		}
		// 对密码进行加密后验证
		UsernamePasswordToken token = new UsernamePasswordToken(username, password);
		// 获取当前的Subject
		Subject currentUser = SecurityUtils.getSubject();
		try {
			// 在调用了login方法后,SecurityManager会收到AuthenticationToken,并将其发送给已配置的Realm执行必须的认证检查
			// 每个Realm都能在必要时对提交的AuthenticationTokens作出反应
			// 所以这一步在调用login(token)方法时,它会走到MyRealm.doGetAuthenticationInfo()方法中,具体验证方式详见此方法
			logger.info("对用户[" + username + "]进行登录验证..验证开始");
			currentUser.login(token);
			logger.info("对用户[" + username + "]进行登录验证..验证通过");
		} catch (UnknownAccountException uae) {
			logger.info("对用户[" + username + "]进行登录验证..验证未通过,未知账户");
			redirectAttributes.addFlashAttribute("message", "未知账户");
		} catch (IncorrectCredentialsException ice) {
			logger.info("对用户[" + username + "]进行登录验证..验证未通过,错误的凭证");
			redirectAttributes.addFlashAttribute("message", "密码不正确");
		} catch (LockedAccountException lae) {
			logger.info("对用户[" + username + "]进行登录验证..验证未通过,账户已锁定");
			redirectAttributes.addFlashAttribute("message", "账户已锁定");
		} catch (ExcessiveAttemptsException eae) {
			// logger.info("对用户[" + username + "]进行登录验证..验证未通过,错误次数大于5次,账户已锁定");
			redirectAttributes.addFlashAttribute("message", "用户名或密码错误次数大于5次,账户已锁定");
		} catch (DisabledAccountException sae) {
			logger.info("对用户[" + username + "]进行登录验证..验证未通过,帐号已经禁止登录");
			redirectAttributes.addFlashAttribute("message", "帐号已经禁止登录");
		} catch (AuthenticationException ae) {
			// 通过处理Shiro的运行时AuthenticationException就可以控制用户登录失败或密码错误时的情景
			logger.info("对用户[" + username + "]进行登录验证..验证未通过,堆栈轨迹如下");
			ae.printStackTrace();
			redirectAttributes.addFlashAttribute("message", "用户名或密码不正确");
		}
		// 验证是否登录成功
		if (currentUser.isAuthenticated()) {
			return "/index";
		} else {
			token.clear();
			return "redirect:loginindex";
		}
	}

	@RequestMapping("/403")
	public String unauthorizedRole() {
		System.out.println("------没有权限-------");
		return "403";
	}

	@RequestMapping("/logOut")
	public String logOut(HttpServletRequest request) {
		Subject subject = SecurityUtils.getSubject();
		subject.logout();
		// session.removeAttribute("user");
		return "login";
	}

}