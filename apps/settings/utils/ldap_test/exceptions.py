"""
LDAP Test exception.
"""


class TestAuthLDAPServerURIError(Exception):
    """LDAP config server connect error"""
    pass


class TestAuthLDAPBindDNError(Exception):
    """LDAP config DN error"""
    pass


class TestAuthLDAPSearchFilterError(Exception):
    """LDAP config search filter Error"""
    pass


class TestAuthLDAPAttrMapError(Exception):
    """LDAP config attr map error"""
    pass


class TestAuthLDAPUserLoginError(Exception):
    """LDAP user login error"""
    pass


class TestAuthLDAPEnabledError(Exception):
    """LDAP config AUTH_LDAP is not enable """
    pass


