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

    def grant_permission(self, key, perm_type='read'):
        """
        Grant permission to this role.

        :param key: The key path where role can have perms on
        :type key: str
        :param perm_type: The type of permission to apply.
                          It can be one of 'read', 'write', 'readwrite'
        :type perm_type: str
        """
        self._etcd_client.grant_permission_role(self.name, key, perm_type)

    def revoke_permission(self, key, range_end):
        """
        Revoke permission from one role.

        :param key: The key path in Etcd
        :type key: str
        :param range_end: ---
        :type range_end: ---
        """
        self._etcd_client.revoke_permission_role(self.name, key, range_end)

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
