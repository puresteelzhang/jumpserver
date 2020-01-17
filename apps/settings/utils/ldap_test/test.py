# coding: utf-8
#
"""
LDAP 测试工具
"""

from django.conf import settings


class LDAPConfigTest(object):
    """
    1. 测试LDAPServer、Port可以连接性
    2. 测试管理账号DN用户名、密码正确性
    3. 测试获取回来的用户信息的属性映射字段
    4. 测试用户过滤器配置是否正确
    5. 测试普通用户登录
    """

    def __init__(self):
        self.config = self.load_config()

    @staticmethod
    def load_config():
        config = {
            'server_uri': settings.AUTH_LDAP_SERVER_URI,
            'bind_dn': settings.AUTH_LDAP_BIND_DN,
            'password':  settings.AUTH_LDAP_BIND_PASSWORD,
            'search_ou': settings.AUTH_LDAP_SEARCH_OU,
            'search_filter': settings.AUTH_LDAP_SEARCH_FILTER,
            'attr_map': settings.AUTH_LDAP_USER_ATTR_MAP,
            'auth_ldap': settings.AUTH_LDAP
        }
        return config

    def test_server_uri(self):
        pass

    def test_bind_dn(self):
        pass

    def test_search_filter(self):
        pass

    def test_attr_map(self):
        pass

    def test_user_login(self):
        pass

    def test_auth_ldap_enable(self):
        pass

