# coding: utf-8
#
"""
LDAP 测试工具
"""

from django.conf import settings


class LDAPConfigTest(object):
    """
    1. 测试LDAPServer、Port可以连接性 - OK
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
        import socket
        server_uri = self.config.get('server_uri', '')
        start = server_uri.find('//')
        if start == -1:
            print('Error: Server uri does not contain ldap:// or ldaps://')
            return False
        end = server_uri.rfind(':')
        if end == -1:
            print('Error: Server uri does not contain port')
            return False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            host = server_uri[start + 2:end]
            port = int(server_uri[end+1:])
            s.connect((host, port))
        except ConnectionRefusedError as e:
            print('Error: The server uri is unconnectable: {}'.format(e))
            return False
        except Exception as e:
            print('Error: {}'.format(e))
            return False
        else:
            print('Success: Test server uri are connectable')
            return True
        finally:
            s.close()

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

