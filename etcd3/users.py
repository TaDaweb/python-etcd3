class User(object):
    """
    An Etcd user.

    :ivar name: name of the user
    """

    def __init__(self, name, roles=[], etcd_client=None):
        self.name = name
        self.roles = roles
        self._etcd_client = etcd_client

    def change_password(self, password):
        """
        Update the password for this user.

        :param password: The new password
        :type password: str
        """
        self._etcd_client.change_password_user(self.name, password)

    def grant_role(self, role):
        """
        Grant role to this user.

        :param role: The name of the role to be granted
        :type role: str
        """
        self.roles = self._etcd_client.grant_role_user(self.name, role).roles

    def revoke_role(self, role):
        """
        Revoke the role from the current user.

        :param role: The name of the role to be revoked
        :type role: str
        """
        self.roles = self._etcd_client.revoke_role_user(self.name, role).roles

    def delete(self):
        """Remove the user from Etcd."""
        self._etcd_client.delete_user(self.name)

    def authenticate(self, password):
        """
        Authenticate with this user and password.

        :param password: The password for the user authentication in etcd
        :type password: str
        """
        self._etcd_client.authenticate(self.name, self.password)

    def __str__(self):
        return ('User name: {name}\n'
                '    Roles: [{roles}]'.format(name=self.name,
                                              roles=', '.join(self.roles)))
