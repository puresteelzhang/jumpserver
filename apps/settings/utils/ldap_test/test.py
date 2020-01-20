# coding: utf-8
#
"""
LDAP 测试工具
"""

import ldap3
from django.conf import settings
from ldap3 import SIMPLE
from ldap3.core.exceptions import (
    LDAPSocketOpenError,
    LDAPSocketReceiveError,
    LDAPSessionTerminatedByServerError,
    LDAPUserNameIsMandatoryError,
    LDAPPasswordIsMandatoryError,
    LDAPInvalidDnError,
)

from common.utils import get_logger

logger = get_logger(__file__)


class LDAPConfigTest(object):
    """
    1. 测试LDAPServer、Port可以连接性 - OK
    2. 测试管理账号DN用户名、密码正确性
    3. 测试获取回来的用户信息的属性映射字段
    4. 测试用户过滤器配置是否正确
    5. 测试普通用户登录
    """

    def __init__(self):
        self.config = {}
        self.load_config()

    def load_config(self):
        self.config = {
            'server_uri': settings.AUTH_LDAP_SERVER_URI,
            'bind_dn': settings.AUTH_LDAP_BIND_DN,
            'password':  settings.AUTH_LDAP_BIND_PASSWORD,
            'search_ou': settings.AUTH_LDAP_SEARCH_OU,
            'search_filter': settings.AUTH_LDAP_SEARCH_FILTER,
            'attr_map': settings.AUTH_LDAP_USER_ATTR_MAP,
            'auth_ldap': settings.AUTH_LDAP
        }

    def _test(self, authentication=None, user=None, password=None):
        host = self.config.get('server_uri')
        server = ldap3.Server(host)
        connection = ldap3.Connection(
            server, user=user, password=password, authentication=authentication
        )
        ret = connection.bind()
        return ret

    def test_server_uri(self):
        self._test()

    def test_bind_dn(self):
        user = self.config.get('bind_dn')
        password = self.config.get('password')
        ret = self._test(authentication=SIMPLE, user=user, password=password)
        if not ret:
            raise LDAPInvalidDnError('bind dn or password incorrect')

    def test_search_ou(self):
        pass

    def test_attr_map(self):
        pass

    def test_search_filter(self):
        pass

    def test_user_login(self):
        pass

    def test_auth_ldap_enable(self):
        return self.config.get('auth_ldap')

    def test(self):
        try:
            self.test_server_uri()
            self.test_bind_dn()
            self.test_attr_map()
            self.test_search_filter()
            self.test_user_login()
        except LDAPSocketOpenError as e:
            msg = "Error (LDAP server): Host or port is disconnected => {}"
            logger.error(msg.format(e), exc_info=True)
        except LDAPSessionTerminatedByServerError as e:
            msg = "Error (LDAP server): " \
                  "The port is not the port of the LDAP service => {}"
            logger.error(msg.format(e), exc_info=True)
        except LDAPSocketReceiveError as e:
            msg = "Error (LDAP server): Please enter the certificate => {}"
            logger.error(msg.format(e), exc_info=True)
        except LDAPUserNameIsMandatoryError as e:
            msg = "Error (Bind dn): Please enter bind dn=> {}"
            logger.error(msg.format(e), exc_info=True)
        except LDAPPasswordIsMandatoryError as e:
            msg = "Error (Bind dn): Please enter password => {}"
            logger.error(msg.format(e), exc_info=True)
        except LDAPInvalidDnError as e:
            msg = "Error (Bind dn): Please enter correct bind dn and password => {}"
            logger.error(msg.format(e), exc_info=True)

        except Exception as e:
            logger.error("Error: {}".format(e), exc_info=True)
        else:
            pass


