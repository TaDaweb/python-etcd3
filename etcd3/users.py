class User(object):
    """
    An Etcd user .

    :ivar name: name of the user
    """

    def __init__(self, name, roles=[], etcd_client=None):
        self.name = name
        self.roles = roles
        self._etcd_client = etcd_client

    def __str__(self):
        return ('User name: {name}\n'
                '  Password: <redacted>\n'
                '  Roles: {roles}'.format(name=self.name, roles=self.roles))
