import etcdrpc


class Role(object):
    """
    An Etcd role.

    :ivar name: name of the user
    :ivar permissions: list of role permissions
    """

    def __init__(self, name, perm=[], etcd_client=None):
        self.name = name
        self.perm = perm
        self._etcd_client = etcd_client

    def delete(self):
        """Delete role from Etcd."""
        self._etcd_client.delete_role(self.name)

    def grant_permission(self, key, end_key=None, perm_type='read',
                         prefix=False, from_key=False):
        """
        Grant permission to this role.

        :param key: the key path of the Etcd on which the permission
                    must be effective
        :type key: str
        :param end_key: the end key of the range
        :type end_key: str
        :param perm_type: the permission type, one of 'read', 'write',
                          'readwrite'
        :type perm_type: str
        :param prefix: apply to the key as a prefix
        :type prefix: bool
        :param from_key: apply to key as an empty upper bound
        :type from_key: bool
        """
        self.perm = self._etcd_client.grant_role_permission(
            self.name, key, perm_type=perm_type,
            prefix=prefix, from_key=from_key).perm

    def revoke_permission(self, key, end_key=None,
                          prefix=False, from_key=False):
        """
        Revoke permission from one role.

        :param key: the key path of the Etcd
        :type key: str
        :param end_key: the end key if a range must be revoked
        :type end_key: str
        :param prefix: apply to the key as a prefix
        :type prefix: bool
        :param from_key: apply to key as an empty upper bound
        :type from_key: bool
        """
        self._etcd_client.revoke_role_permission(self.name, key,
                                                 end_key=end_key,
                                                 prefix=prefix,
                                                 from_key=from_key)
        self.perm = self._etcd_client.get_role(self.name).perm

    def __str__(self):
        def convert(v):
            if v == etcdrpc.Permission.READ:
                return 'read'
            elif v == etcdrpc.Permission.WRITE:
                return 'write'
            elif v == etcdrpc.Permission.READWRITE:
                return 'readwrite'

        def print_line(p):
            return ' ' * 8 + p[0] + ' ' * (15 - len(p[0])) + p[1] + '\n'

        permissions = ''.join([print_line((convert(p.permType), p.key))
                              for p in self.perm])

        return ('Role name: {name}\n'
                '    Permissions: \n{perm}'.format(name=self.name,
                                                   perm=permissions))
