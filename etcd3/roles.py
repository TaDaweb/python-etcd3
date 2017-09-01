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

    def __str__(self):
        return ('Role name: {name}\n'
                '  Permissions: {perm}'.format(name=self.name,
                                               perm=self.perm))
