package com.spring.mybatis.realm;

import com.spring.mybatis.model.User;
import com.spring.mybatis.service.RoleService;
import com.spring.mybatis.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.subject.PrincipalCollection;

import javax.annotation.Resource;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 用户授权信息域
 * 
 * @author coderhuang
 * 
 */
	public class UserRealm extends CasRealm {
	
	@Resource
	private RoleService roleService;

	@Resource
	private UserService userService;

	protected final Map<String, SimpleAuthorizationInfo> roles = new ConcurrentHashMap<String, SimpleAuthorizationInfo>();
	
	/**
	 * 设置角色和权限信息
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String account = (String) principals.getPrimaryPrincipal();
		SimpleAuthorizationInfo authorizationInfo = null;
		if (authorizationInfo == null) {
			authorizationInfo = new SimpleAuthorizationInfo();
			authorizationInfo.addStringPermissions(roleService.getPermissions(account));
			authorizationInfo.addRoles(roleService.getRoles(account));
			roles.put(account, authorizationInfo);
		}

		return authorizationInfo;
	}
	
	
	/**
	 * 1、CAS认证 ,验证用户身份
	 * 2、将用户基本信息设置到会话中
	 */
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
		System.out.println("=======================================================");
		//此步骤是执行验证ST是否有效
		AuthenticationInfo authc = super.doGetAuthenticationInfo(token);

		String account = (String) authc.getPrincipals().getPrimaryPrincipal();

		User user = userService.getUserByAccount(account);
		
		SecurityUtils.getSubject().getSession().setAttribute("user", user);

		return authc;
	}
	

}
