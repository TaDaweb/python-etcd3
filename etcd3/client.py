import functools
import inspect
import threading

import grpc
import grpc._channel

from six.moves import queue

import etcd3.etcdrpc as etcdrpc
import etcd3.exceptions as exceptions
import etcd3.leases as leases
import etcd3.locks as locks
import etcd3.members
import etcd3.roles as roles
import etcd3.transactions as transactions
import etcd3.users as users
import etcd3.utils as utils
import etcd3.watch as watch

_EXCEPTIONS_BY_CODE = {
    grpc.StatusCode.INTERNAL: exceptions.InternalServerError,
    grpc.StatusCode.UNAVAILABLE: exceptions.ConnectionFailedError,
    grpc.StatusCode.DEADLINE_EXCEEDED: exceptions.ConnectionTimeoutError,
    grpc.StatusCode.FAILED_PRECONDITION: exceptions.PreconditionFailedError,
    grpc.StatusCode.UNAUTHENTICATED: exceptions.UnauthenticatedError,
    grpc.StatusCode.INVALID_ARGUMENT: exceptions.InvalidArgumentError,
    grpc.StatusCode.PERMISSION_DENIED: exceptions.PermissionDeniedError,
    grpc.StatusCode.ALREADY_EXISTS: exceptions.AlreadyExistsError,
    grpc.StatusCode.ABORTED: exceptions.AbortedError,
    grpc.StatusCode.DEADLINE_EXCEEDED: exceptions.DeadlineExceededError,
    grpc.StatusCode.UNKNOWN: exceptions.UnknownError,
}


def _translate_exception(exc):
    code = exc.code()
    exception = _EXCEPTIONS_BY_CODE.get(code)(exc._state.details)
    if exception is None:
        raise
    raise exception


def _handle_errors(f):
    if inspect.isgeneratorfunction(f):
        def handler(*args, **kwargs):
            try:
                for data in f(*args, **kwargs):
                    yield data
            except grpc.RpcError as exc:
                _translate_exception(exc)
    else:
        def handler(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except grpc.RpcError as exc:
                _translate_exception(exc)

    return functools.wraps(f)(handler)


class Transactions(object):
    def __init__(self):
        self.value = transactions.Value
        self.version = transactions.Version
        self.create = transactions.Create
        self.mod = transactions.Mod

        self.put = transactions.Put
        self.get = transactions.Get
        self.delete = transactions.Delete


class KVMetadata(object):
    def __init__(self, keyvalue):
        self.key = keyvalue.key
        self.create_revision = keyvalue.create_revision
        self.mod_revision = keyvalue.mod_revision
        self.version = keyvalue.version
        self.lease_id = keyvalue.lease


class Status(object):
    def __init__(self, version, db_size, leader, raft_index, raft_term):
        self.version = version
        self.db_size = db_size
        self.leader = leader
        self.raft_index = raft_index
        self.raft_term = raft_term


class Alarm(object):
    def __init__(self, alarm_type, member_id):
        self.alarm_type = alarm_type
        self.member_id = member_id


class SimpleTokenCallCredentials(grpc.AuthMetadataPlugin):
    """Metadata wrapper for raw access token credentials."""

    def __init__(self, access_token):
        self._access_token = access_token

    def __call__(self, context, callback):
        metadata = (('token', self._access_token),)
        callback(metadata, None)


class Etcd3Client(object):
    def __init__(self, host='localhost', port=2379,
                 ca_cert=None, cert_key=None, cert_cert=None,
                 timeout=None):
        self._url = '{host}:{port}'.format(host=host, port=port)
        self.uses_secure_channel, self.channel = \
            self._create_channel(ca_cert, cert_key, cert_cert)
        self._credentials = None
        self._metadata = []
        self.timeout = timeout
        self.authstub = etcdrpc.AuthStub(self.channel)
        self.kvstub = etcdrpc.KVStub(self.channel)
        self.watcher = watch.Watcher(etcdrpc.WatchStub(self.channel),
                                     timeout=self.timeout)
        self.clusterstub = etcdrpc.ClusterStub(self.channel)
        self.leasestub = etcdrpc.LeaseStub(self.channel)
        self.maintenancestub = etcdrpc.MaintenanceStub(self.channel)
        self.transactions = Transactions()

    def _create_channel(self, ca_cert, cert_key, cert_cert):
        if ca_cert is None:
            return False, grpc.insecure_channel(self._url)

        cert_params = [c is not None for c in (cert_cert, cert_key)]
        # if all cert params are all True or all False then skip.
        # raise an error if one of them is different.
        # key or cert left unset
        if not (all(cert_params) or
                not (any(cert_params) or all(cert_params))):
            raise ValueError(
                'to use a secure channel ca_cert is required by itself, '
                'or cert_cert and cert_key must be specified.')
        creds_ssl = self._get_secure_creds(ca_cert,
                                           cert_key,
                                           cert_cert)
        credentials = grpc.ssl_channel_credentials(creds_ssl)
        return True, grpc.secure_channel(self._url, credentials)

    def _get_secure_creds(self, ca_cert, cert_key=None, cert_cert=None):
        cert_key_file = None
        cert_cert_file = None

        with open(ca_cert, 'rb') as f:
            ca_cert_file = f.read()

        if cert_key is not None:
            with open(cert_key, 'rb') as f:
                cert_key_file = f.read()

        if cert_cert is not None:
            with open(cert_cert, 'rb') as f:
                cert_cert_file = f.read()

        return grpc.ssl_channel_credentials(
            ca_cert_file,
            cert_key_file,
            cert_cert_file
        )

    @_handle_errors
    def enable_auth(self):
        """Enable Authentication in Etcd."""
        auth_enable_request = etcdrpc.AuthEnableRequest()
        self.authstub.AuthEnable(auth_enable_request,
                                 metadata=self._metadata,
                                 timeout=self.timeout)

    @_handle_errors
    def disable_auth(self):
        """Disable Authentication in Etcd."""
        auth_disable_request = etcdrpc.AuthDisableRequest()
        self.authstub.AuthDisable(auth_disable_request,
                                  metadata=self._metadata,
                                  timeout=self.timeout)

    @_handle_errors
    def authenticate(self, username=None, password=None):
        """
        Authenticate against the Etcd cluster.

        :param username: the name of the authentication user
        :type username: str
        :param password: the password of the the authentication user
        :type password: str
        """
        creds = [c is not None for c in (username, password)]
        if not any(creds):
            raise ValueError('To Authenticate the username and password '
                             'must be specified')
        cred_user = utils.to_bytes(username)
        cred_pass = utils.to_bytes(password)
        authenticate_request = etcdrpc.AuthenticateRequest(name=cred_user,
                                                           password=cred_pass)
        authenticate_response = \
            self.authstub.Authenticate(authenticate_request,
                                       timeout=self.timeout)
        self._metadata = filter(lambda x: x[0] != 'token', self._metadata)
        self._metadata.append(('token', authenticate_response.token))
        # credentials is set but not currently used.
        # After creating and setting it into the calls is not working.
        self._credentials = grpc.metadata_call_credentials(
            SimpleTokenCallCredentials(authenticate_response.token))

    @_handle_errors
    def add_user(self, username, password):
        """
        Add a user in the Etcd cluster.

        example usage:

        .. code-block:: python

            >>> import etcd3
            >>> etcd = etcd3.client()
            >>> etcd.add_user('root', 'testpass')
            User Name: root
                Roles: []

        :param username: the name of the user to be created
        :type username: str
        :param password: the password for the users
        :type password: str
        :returns: the user just created
        :rtype: :class:`User`
        """
        auth_user_add_request = etcdrpc.AuthUserAddRequest(name=username,
                                                           password=password)
        self.authstub.UserAdd(auth_user_add_request,
                              metadata=self._metadata,
                              timeout=self.timeout)

        return users.User(name=username, etcd_client=self)

    @_handle_errors
    def get_user(self, username):
        """
        Get the user information with roles.

        :param username: the name of the user
        :type username: str
        :returns: the user object
        :rtype: :class:`User`
        """
        auth_user_get_request = etcdrpc.AuthUserGetRequest(name=username)
        auth_user_get_response = self.authstub.UserGet(auth_user_get_request,
                                                       metadata=self._metadata,
                                                       timeout=self.timeout)
        return users.User(name=username,
                          roles=auth_user_get_response.roles,
                          etcd_client=self)

    @_handle_errors
    def list_user(self):
        """
        Return an iterable with the list of all users.

        :returns: a generator with :class:`User`
        """
        auth_user_list_request = etcdrpc.AuthUserListRequest()
        auth_user_list_response = self.authstub.UserList(
            auth_user_list_request,
            metadata=self._metadata,
            timeout=self.timeout)
        for user in auth_user_list_response.users:
            yield users.User(user, etcd_client=self)

    @_handle_errors
    def delete_user(self, username):
        """
        Delete an user from the cluster.

        :param username: the name of the user to be removed
        :type username: str
        """
        auth_user_delete_request = etcdrpc.AuthUserDeleteRequest(name=username)
        self.authstub.UserDelete(auth_user_delete_request,
                                 metadata=self._metadata,
                                 timeout=self.timeout)

    @_handle_errors
    def change_password_user(self, username, password):
        """
        Update the password for a user.

        :param username: the name of the user
        :type username: str
        :param password: the new password for the user
        :type password: str
        :returns: the user object
        :rtype: :class:`User`
        """
        auth_user_change_password_request = \
            etcdrpc.AuthUserChangePasswordRequest(name=username,
                                                  password=password)
        self.authstub.UserChangePassword(auth_user_change_password_request,
                                         metadata=self._metadata,
                                         timeout=self.timeout)

    @_handle_errors
    def grant_role_user(self, username, rolename):
        """
        Grant a role to an user.

        :param username: the name of the user to be modified
        :type username: str
        :param rolename: the name of the role to be added to the user
        :type rolename: str
        :returns: the user object
        :rtype: :class:`User`
        """
        auth_user_grant_role_request = \
            etcdrpc.AuthUserGrantRoleRequest(user=username,
                                             role=rolename)
        self.authstub.UserGrantRole(auth_user_grant_role_request,
                                    metadata=self._metadata,
                                    timeout=self.timeout)
        return self.get_user(username)

    @_handle_errors
    def revoke_role_user(self, username, rolename):
        """
        Revoke a role from an user.

        :param username: the name of the user to be modified
        :type username: str
        :param rolename: the name of the role to be added to the user
        :type rolename: str
        :returns: the user object
        :rtype: :class:`User`
        """
        auth_user_revoke_role_request = \
            etcdrpc.AuthUserRevokeRoleRequest(name=username,
                                              role=rolename)
        self.authstub.UserRevokeRole(auth_user_revoke_role_request,
                                     metadata=self._metadata,
                                     timeout=self.timeout)
        return self.get_user(username)

    @_handle_errors
    def add_role(self, rolename):
        """
        Add a role to the Etcd cluster.

        :param rolename: the name of the new role to be added. must be unique
        :type rolename: str
        :returns: the role object
        :rtype: :class:`Role`
        """
        auth_role_add_request = etcdrpc.AuthRoleAddRequest(name=rolename)
        self.authstub.RoleAdd(auth_role_add_request,
                              metadata=self._metadata,
                              timeout=self.timeout)
        return roles.Role(rolename, etcd_client=self)

    @_handle_errors
    def get_role(self, rolename):
        """
        Get a role and its information in Etcd cluster.

        :param rolename: the name of the role to be fetchec. It must exist
        :type rolename: str
        :returns: the role object
        :rtype: :class:`Role`
        """
        auth_role_get_request = etcdrpc.AuthRoleGetRequest(role=rolename)
        auth_role_get_response = self.authstub.RoleGet(auth_role_get_request,
                                                       metadata=self._metadata,
                                                       timeout=self.timeout)
        return roles.Role(rolename, auth_role_get_response.perm,
                          etcd_client=self)

    @_handle_errors
    def list_role(self):
        """
        List all the roles into the cluster.

        :returns: a generator with :class:`Role`
        """
        auth_role_list_request = etcdrpc.AuthRoleListRequest()
        auth_role_list_response = \
            self.authstub.RoleList(auth_role_list_request,
                                   metadata=self._metadata,
                                   timeout=self.timeout)
        for role in auth_role_list_response.roles:
            yield roles.Role(role, etcd_client=self)

    @_handle_errors
    def delete_role(self, rolename):
        """
        Delete a role from the cluster.

        :param rolename: the name of the role to be removed
        :type rolename: str
        """
        auth_role_delete_request = \
            etcdrpc.AuthRoleDeleteRequest(role=rolename)
        self.authstub.RoleDelete(auth_role_delete_request,
                                 metadata=self._metadata,
                                 timeout=self.timeout)

    def _build_role_permission(self, key,
                               perm_type='read',
                               range_end=None):
        permission = etcdrpc.Permission()

        permission.key = key
        if range_end is not None:
            permission.range_end = utils.to_bytes(range_end)

        if perm_type == 'read':
            permission.permType = etcdrpc.Permission.READ
        elif perm_type == 'write':
            permission.permType = etcdrpc.Permission.WRITE
        elif perm_type == 'readwrite':
            permission.permType = etcdrpc.Permission.READWRITE
        else:
            raise ValueError('per_type must be one of "read", '
                             '"write", "readwrite"')
        return permission

    def _range_end_from_perm_flag(self, start_key, end_key,
                                  prefix=False, from_key=False):
        if prefix and from_key:
            raise ValueError('prefix and from_key are mutually exclusive')

        if end_key is not None and (prefix or from_key):
            if prefix:
                raise ValueError('unexpected end_key with prefix flag')
            if from_key:
                raise ValueError('unexpected from_key with prefix flag')

        if prefix:
            return utils.increment_last_byte(utils.to_bytes(start_key))
        if from_key:
            return "\x00"
        if end_key is None:
            return ''
        return end_key

    @_handle_errors
    def grant_role_permission(self, rolename, key, end_key=None,
                              perm_type='read', prefix=False, from_key=False):
        """
        Grant a permission on a role.

        :param rolename: the name of the role to be changed
        :type rolename: str
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
        :returns: the role with the permissions :class:`Role`
        """
        range_end = self._range_end_from_perm_flag(key, end_key,
                                                   prefix, from_key)

        permission = self._build_role_permission(key,
                                                 perm_type=perm_type,
                                                 range_end=range_end)
        auth_role_grant_perm_request = \
            etcdrpc.AuthRoleGrantPermissionRequest(name=rolename,
                                                   perm=permission)
        self.authstub.RoleGrantPermission(auth_role_grant_perm_request,
                                          metadata=self._metadata,
                                          timeout=self.timeout)
        return self.get_role(rolename)

    @_handle_errors
    def revoke_role_permission(self, rolename, key, end_key=None,
                               prefix=False, from_key=False):
        """
        Revoke a permission on a role.

        :param rolename: the name of the role to be changed
        :type rolename: str
        :param key: the key path of the Etcd
        :type key: str
        :param end_key: the end key if a range must be revoked
        :type end_key: str
        :param prefix: apply to the key as a prefix
        :type prefix: bool
        :param from_key: apply to key as an empty upper bound
        :type from_key: bool
        """
        range_end = self._range_end_from_perm_flag(key, end_key,
                                                   prefix, from_key)
        auth_role_revoke_perm_request = \
            etcdrpc.AuthRoleRevokePermissionRequest(role=rolename,
                                                    key=key,
                                                    range_end=range_end)
        self.authstub.RoleRevokePermission(auth_role_revoke_perm_request,
                                           metadata=self._metadata,
                                           timeout=self.timeout)
        return self.get_role(rolename)

    def _build_get_range_request(self, key,
                                 range_end=None,
                                 limit=None,
                                 revision=None,
                                 sort_order=None,
                                 sort_target='key',
                                 serializable=None,
                                 keys_only=None,
                                 count_only=None,
                                 min_mod_revision=None,
                                 max_mod_revision=None,
                                 min_create_revision=None,
                                 max_create_revision=None):
        range_request = etcdrpc.RangeRequest()
        range_request.key = utils.to_bytes(key)
        if range_end is not None:
            range_request.range_end = utils.to_bytes(range_end)

        if sort_order is None:
            range_request.sort_order = etcdrpc.RangeRequest.NONE
        elif sort_order == 'ascend':
            range_request.sort_order = etcdrpc.RangeRequest.ASCEND
        elif sort_order == 'descend':
            range_request.sort_order = etcdrpc.RangeRequest.DESCEND
        else:
            raise ValueError('unknown sort order: "{}"'.format(sort_order))

        if sort_target is None or sort_target == 'key':
            range_request.sort_target = etcdrpc.RangeRequest.KEY
        elif sort_target == 'version':
            range_request.sort_target = etcdrpc.RangeRequest.VERSION
        elif sort_target == 'create':
            range_request.sort_target = etcdrpc.RangeRequest.CREATE
        elif sort_target == 'mod':
            range_request.sort_target = etcdrpc.RangeRequest.MOD
        elif sort_target == 'value':
            range_request.sort_target = etcdrpc.RangeRequest.VALUE
        else:
            raise ValueError('sort_target must be one of "key", '
                             '"version", "create", "mod" or "value"')

        return range_request

    @_handle_errors
    def get(self, key):
        """
        Get the value of a key from etcd.

        example usage:

        .. code-block:: python

            >>> import etcd3
            >>> etcd = etcd3.client()
            >>> etcd.get('/thing/key')
            'hello world'

        :param key: key in etcd to get
        :returns: value of key and metadata
        :rtype: bytes, ``KVMetadata``
        """
        range_request = self._build_get_range_request(key)
        range_response = self.kvstub.Range(range_request,
                                           metadata=self._metadata,
                                           timeout=self.timeout)

        if range_response.count < 1:
            return None, None
        else:
            kv = range_response.kvs.pop()
            return kv.value, KVMetadata(kv)

    @_handle_errors
    def get_prefix(self, key_prefix, sort_order=None, sort_target='key'):
        """
        Get a range of keys with a prefix.

        :param key_prefix: first key in range

        :returns: sequence of (value, metadata) tuples
        """
        range_request = self._build_get_range_request(
            key=key_prefix,
            range_end=utils.increment_last_byte(utils.to_bytes(key_prefix)),
            sort_order=sort_order,
        )

        range_response = self.kvstub.Range(range_request,
                                           metadata=self._metadata,
                                           timeout=self.timeout)

        if range_response.count < 1:
            return
        else:
            for kv in range_response.kvs:
                yield (kv.value, KVMetadata(kv))

    @_handle_errors
    def get_all(self, sort_order=None, sort_target='key'):
        """
        Get all keys currently stored in etcd.

        :returns: sequence of (value, metadata) tuples
        """
        range_request = self._build_get_range_request(
            key=b'\0',
            range_end=b'\0',
            sort_order=sort_order,
            sort_target=sort_target,
        )

        range_response = self.kvstub.Range(range_request,
                                           metadata=self._metadata,
                                           timeout=self.timeout)

        if range_response.count < 1:
            return
        else:
            for kv in range_response.kvs:
                yield (kv.value, KVMetadata(kv))

    def _build_put_request(self, key, value, lease=None):
        put_request = etcdrpc.PutRequest()
        put_request.key = utils.to_bytes(key)
        put_request.value = utils.to_bytes(value)
        put_request.lease = utils.lease_to_id(lease)
        return put_request

    @_handle_errors
    def put(self, key, value, lease=None):
        """
        Save a value to etcd.

        Example usage:

        .. code-block:: python

            >>> import etcd3
            >>> etcd = etcd3.client()
            >>> etcd.put('/thing/key', 'hello world')

        :param key: key in etcd to set
        :param value: value to set key to
        :type value: bytes
        :param lease: Lease to associate with this key.
        :type lease: either :class:`.Lease`, or int (ID of lease)
        """
        put_request = self._build_put_request(key, value, lease=lease)
        self.kvstub.Put(put_request,
                        metadata=self._metadata,
                        timeout=self.timeout)

    @_handle_errors
    def replace(self, key, initial_value, new_value):
        """
        Atomically replace the value of a key with a new value.

        This compares the current value of a key, then replaces it with a new
        value if it is equal to a specified value. This operation takes place
        in a transaction.

        :param key: key in etcd to replace
        :param initial_value: old value to replace
        :type initial_value: bytes
        :param new_value: new value of the key
        :type new_value: bytes
        :returns: status of transaction, ``True`` if the replace was
                  successful, ``False`` otherwise
        :rtype: bool
        """
        status, _ = self.transaction(
            compare=[self.transactions.value(key) == initial_value],
            success=[self.transactions.put(key, new_value)],
            failure=[],
        )

        return status

    def _build_delete_request(self, key,
                              range_end=None,
                              prev_kv=None):
        delete_request = etcdrpc.DeleteRangeRequest()
        delete_request.key = utils.to_bytes(key)

        if range_end is not None:
            delete_request.range_end = utils.to_bytes(range_end)

        if prev_kv is not None:
            delete_request.prev_kv = prev_kv

        return delete_request

    @_handle_errors
    def delete(self, key):
        """
        Delete a single key in etcd.

        :param key: key in etcd to delete
        :returns: True if the key has been deleted
        """
        delete_request = self._build_delete_request(key)
        delete_response = self.kvstub.DeleteRange(
            delete_request,
            metadata=self._metadata,
            timeout=self.timeout)
        return delete_response.deleted >= 1

    @_handle_errors
    def delete_prefix(self, prefix):
        """Delete a range of keys with a prefix in etcd."""
        delete_request = self._build_delete_request(
            prefix,
            range_end=utils.increment_last_byte(utils.to_bytes(prefix))
        )
        return self.kvstub.DeleteRange(delete_request,
                                       metadata=self._metadata,
                                       timeout=self.timeout)

    @_handle_errors
    def status(self):
        """Get the status of the responding member."""
        status_request = etcdrpc.StatusRequest()
        status_response = self.maintenancestub.Status(status_request,
                                                      metadata=self._metadata,
                                                      timeout=self.timeout)

        for m in self.members:
            if m.id == status_response.leader:
                leader = m
                break
        else:
            # raise exception?
            leader = None

        return Status(status_response.version,
                      status_response.dbSize,
                      leader,
                      status_response.raftIndex,
                      status_response.raftTerm)

    @_handle_errors
    def add_watch_callback(self, *args, **kwargs):
        """
        Watch a key or range of keys and call a callback on every event.

        If timeout was declared during the client initialization and
        the watch cannot be created during that time the method raises
        a ``WatchTimedOut`` exception.

        :param key: key to watch
        :param callback: callback function

        :returns: watch_id. Later it could be used for cancelling watch.
        """
        try:
            return self.watcher.add_callback(*args, **kwargs)
        except queue.Empty:
            raise exceptions.WatchTimedOut()

    @_handle_errors
    def watch(self, key, **kwargs):
        """
        Watch a key.

        Example usage:

        .. code-block:: python
            events_iterator, cancel = etcd.watch('/doot/key')
            for event in events_iterator:
                print(event)

        :param key: key to watch

        :returns: tuple of ``events_iterator`` and ``cancel``.
                  Use ``events_iterator`` to get the events of key changes
                  and ``cancel`` to cancel the watch request
        """
        event_queue = queue.Queue()

        def callback(event):
            event_queue.put(event)

        watch_id = self.add_watch_callback(key, callback, **kwargs)
        canceled = threading.Event()

        def cancel():
            canceled.set()
            event_queue.put(None)
            self.cancel_watch(watch_id)

        @_handle_errors
        def iterator():
            while not canceled.is_set():
                event = event_queue.get()
                if event is None:
                    canceled.set()
                if isinstance(event, Exception):
                    canceled.set()
                    raise event
                if not canceled.is_set():
                    yield event

        return iterator(), cancel

    @_handle_errors
    def watch_prefix(self, key_prefix, **kwargs):
        """Watches a range of keys with a prefix."""
        kwargs['range_end'] = \
            utils.increment_last_byte(utils.to_bytes(key_prefix))
        return self.watch(key_prefix, **kwargs)

    @_handle_errors
    def watch_once(self, key, timeout=None, **kwargs):
        """
        Watch a key and stops after the first event.

        If the timeout was specified and event didn't arrived method
        will raise ``WatchTimedOut`` exception.

        :param key: key to watch
        :param timeout: (optional) timeout in seconds.
        :returns: ``Event``
        """
        event_queue = queue.Queue()

        def callback(event):
            event_queue.put(event)

        watch_id = self.add_watch_callback(key, callback, **kwargs)

        try:
            return event_queue.get(timeout=timeout)
        except queue.Empty:
            raise exceptions.WatchTimedOut()
        finally:
            self.cancel_watch(watch_id)

    @_handle_errors
    def watch_prefix_once(self, key_prefix, timeout=None, **kwargs):
        """
        Watches a range of keys with a prefix and stops after the first event.

        If the timeout was specified and event didn't arrived method
        will raise ``WatchTimedOut`` exception.
        """
        kwargs['range_end'] = \
            utils.increment_last_byte(utils.to_bytes(key_prefix))
        return self.watch_once(key_prefix, timeout=timeout, **kwargs)

    @_handle_errors
    def cancel_watch(self, watch_id):
        """
        Stop watching a key or range of keys.

        :param watch_id: watch_id returned by ``add_watch_callback`` method
        """
        self.watcher.cancel(watch_id)

    def _ops_to_requests(self, ops):
        """
        Return a list of grpc requests.

        Returns list from an input list of etcd3.transactions.{Put, Get,
        Delete} objects.
        """
        request_ops = []
        for op in ops:
            if isinstance(op, transactions.Put):
                request = self._build_put_request(op.key, op.value, op.lease)
                request_op = etcdrpc.RequestOp(request_put=request)
                request_ops.append(request_op)

            elif isinstance(op, transactions.Get):
                request = self._build_get_range_request(op.key)
                request_op = etcdrpc.RequestOp(request_range=request)
                request_ops.append(request_op)

            elif isinstance(op, transactions.Delete):
                request = self._build_delete_request(op.key)
                request_op = etcdrpc.RequestOp(request_delete_range=request)
                request_ops.append(request_op)

            else:
                raise Exception(
                    'Unknown request class {}'.format(op.__class__))
        return request_ops

    @_handle_errors
    def transaction(self, compare, success=None, failure=None):
        """
        Perform a transaction.

        Example usage:

        .. code-block:: python

            etcd.transaction(
                compare=[
                    etcd.transactions.value('/doot/testing') == 'doot',
                    etcd.transactions.version('/doot/testing') > 0,
                ],
                success=[
                    etcd.transactions.put('/doot/testing', 'success'),
                ],
                failure=[
                    etcd.transactions.put('/doot/testing', 'failure'),
                ]
            )

        :param compare: A list of comparisons to make
        :param success: A list of operations to perform if all the comparisons
                        are true
        :param failure: A list of operations to perform if any of the
                        comparisons are false
        :return: A tuple of (operation status, responses)
        """
        compare = [c.build_message() for c in compare]

        success_ops = self._ops_to_requests(success)
        failure_ops = self._ops_to_requests(failure)

        transaction_request = etcdrpc.TxnRequest(compare=compare,
                                                 success=success_ops,
                                                 failure=failure_ops)
        txn_response = self.kvstub.Txn(transaction_request,
                                       metadata=self._metadata,
                                       timeout=self.timeout)

        responses = []
        for response in txn_response.responses:
            response_type = response.WhichOneof('response')
            if response_type == 'response_put':
                responses.append(None)

            elif response_type == 'response_range':
                range_kvs = []
                for kv in response.response_range.kvs:
                    range_kvs.append((kv.value, KVMetadata(kv)))

                responses.append(range_kvs)

        return txn_response.succeeded, responses

    @_handle_errors
    def lease(self, ttl, lease_id=None):
        """
        Create a new lease.

        All keys attached to this lease will be expired and deleted if the
        lease expires. A lease can be sent keep alive messages to refresh the
        ttl.

        :param ttl: Requested time to live
        :param lease_id: Requested ID for the lease

        :returns: new lease
        :rtype: :class:`.Lease`
        """
        lease_grant_request = etcdrpc.LeaseGrantRequest(TTL=ttl, ID=lease_id)
        lease_grant_response = \
            self.leasestub.LeaseGrant(lease_grant_request,
                                      metadata=self._metadata,
                                      timeout=self.timeout)
        return leases.Lease(lease_id=lease_grant_response.ID,
                            ttl=lease_grant_response.TTL,
                            etcd_client=self)

    @_handle_errors
    def revoke_lease(self, lease_id):
        """
        Revoke a lease.

        :param lease_id: ID of the lease to revoke.
        """
        lease_revoke_request = etcdrpc.LeaseRevokeRequest(ID=lease_id)
        self.leasestub.LeaseRevoke(lease_revoke_request,
                                   metadata=self._metadata,
                                   timeout=self.timeout)

    @_handle_errors
    def refresh_lease(self, lease_id):
        keep_alive_request = etcdrpc.LeaseKeepAliveRequest(ID=lease_id)
        request_stream = [keep_alive_request]
        for response in self.leasestub.LeaseKeepAlive(iter(request_stream),
                                                      metadata=self._metadata,
                                                      timeout=self.timeout):
            yield response

    @_handle_errors
    def get_lease_info(self, lease_id):
        # only available in etcd v3.1.0 and later
        ttl_request = etcdrpc.LeaseTimeToLiveRequest(ID=lease_id,
                                                     keys=True)
        return self.leasestub.LeaseTimeToLive(ttl_request,
                                              metadata=self._metadata,
                                              timeout=self.timeout)

    @_handle_errors
    def lock(self, name, ttl=60):
        """
        Create a new lock.

        :param name: name of the lock
        :type name: string or bytes
        :param ttl: length of time for the lock to live for in seconds. The
                    lock will be released after this time elapses, unless
                    refreshed
        :type ttl: int
        :returns: new lock
        :rtype: :class:`.Lock`
        """
        return locks.Lock(name, ttl=ttl, etcd_client=self)

    @_handle_errors
    def add_member(self, urls):
        """
        Add a member into the cluster.

        :returns: new member
        :rtype: :class:`.Member`
        """
        member_add_request = etcdrpc.MemberAddRequest(peerURLs=urls)

        member_add_response = \
            self.clusterstub.MemberAdd(member_add_request,
                                       metadata=self._metadata,
                                       timeout=self.timeout)
        member = member_add_response.member
        return etcd3.members.Member(member.ID,
                                    member.name,
                                    member.peerURLs,
                                    member.clientURLs,
                                    etcd_client=self)

    @_handle_errors
    def remove_member(self, member_id):
        """
        Remove an existing member from the cluster.

        :param member_id: ID of the member to remove
        """
        member_rm_request = etcdrpc.MemberRemoveRequest(ID=member_id)
        self.clusterstub.MemberRemove(member_rm_request,
                                      metadata=self._metadata,
                                      timeout=self.timeout)

    @_handle_errors
    def update_member(self, member_id, peer_urls):
        """
        Update the configuration of an existing member in the cluster.

        :param member_id: ID of the member to update
        :param peer_urls: new list of peer urls the member will use to
                          communicate with the cluster
        """
        member_update_request = etcdrpc.MemberUpdateRequest(ID=member_id,
                                                            peerURLs=peer_urls)
        self.clusterstub.MemberUpdate(member_update_request,
                                      metadata=self._metadata,
                                      timeout=self.timeout)

    @property
    def members(self):
        """
        List of all members associated with the cluster.

        :type: sequence of :class:`.Member`

        """
        member_list_request = etcdrpc.MemberListRequest()
        member_list_response = \
            self.clusterstub.MemberList(member_list_request,
                                        metadata=self._metadata,
                                        timeout=self.timeout)

        for member in member_list_response.members:
            yield etcd3.members.Member(member.ID,
                                       member.name,
                                       member.peerURLs,
                                       member.clientURLs,
                                       etcd_client=self)

    @_handle_errors
    def compact(self, revision, physical=False):
        """
        Compact the event history in etcd up to a given revision.

        All superseded keys with a revision less than the compaction revision
        will be removed.

        :param revision: revision for the compaction operation
        :param physical: if set to True, the request will wait until the
                         compaction is physically applied to the local database
                         such that compacted entries are totally removed from
                         the backend database
        """
        compact_request = etcdrpc.CompactionRequest(revision=revision,
                                                    physical=physical)
        self.kvstub.Compact(compact_request,
                            metadata=self._metadata,
                            timeout=self.timeout)

    @_handle_errors
    def defragment(self):
        """Defragment a member's backend database to recover storage space."""
        defrag_request = etcdrpc.DefragmentRequest()
        self.maintenancestub.Defragment(defrag_request)

    @_handle_errors
    def hash(self):
        """
        Return the hash of the local KV state.

        :returns: kv state hash
        :rtype: int
        """
        hash_request = etcdrpc.HashRequest()
        return self.maintenancestub.Hash(hash_request).hash

    def _build_alarm_request(self, alarm_action, member_id, alarm_type):
        alarm_request = etcdrpc.AlarmRequest()

        if alarm_action == 'get':
            alarm_request.action = etcdrpc.AlarmRequest.GET
        elif alarm_action == 'activate':
            alarm_request.action = etcdrpc.AlarmRequest.ACTIVATE
        elif alarm_action == 'deactivate':
            alarm_request.action = etcdrpc.AlarmRequest.DEACTIVATE
        else:
            raise ValueError('Unknown alarm action: {}'.format(alarm_action))

        alarm_request.memberID = member_id

        if alarm_type == 'none':
            alarm_request.alarm = etcdrpc.NONE
        elif alarm_type == 'no space':
            alarm_request.alarm = etcdrpc.NOSPACE
        else:
            raise ValueError('Unknown alarm type: {}'.format(alarm_type))

        return alarm_request

    @_handle_errors
    def create_alarm(self, member_id=0):
        """Create an alarm.

        If no member id is given, the alarm is activated for all the
        members of the cluster. Only the `no space` alarm can be raised.

        :param member_id: The cluster member id to create an alarm to.
                          If 0, the alarm is created for all the members
                          of the cluster.
        :returns: list of :class:`.Alarm`
        """
        alarm_request = self._build_alarm_request('activate',
                                                  member_id,
                                                  'no space')
        alarm_response = self.maintenancestub.Alarm(alarm_request,
                                                    metadata=self._metadata,
                                                    timeout=self.timeout)

        return [Alarm(alarm.alarm, alarm.memberID)
                for alarm in alarm_response.alarms]

    @_handle_errors
    def list_alarms(self, member_id=0, alarm_type='none'):
        """List the activated alarms.

        :param member_id:
        :param alarm_type: The cluster member id to create an alarm to.
                           If 0, the alarm is created for all the members
                           of the cluster.
        :returns: sequence of :class:`.Alarm`
        """
        alarm_request = self._build_alarm_request('get',
                                                  member_id,
                                                  alarm_type)
        alarm_response = self.maintenancestub.Alarm(alarm_request,
                                                    metadata=self._metadata,
                                                    timeout=self.timeout)

        for alarm in alarm_response.alarms:
            yield Alarm(alarm.alarm, alarm.memberID)

    @_handle_errors
    def disarm_alarm(self, member_id=0):
        """Cancel an alarm.

        :param member_id: The cluster member id to cancel an alarm.
                          If 0, the alarm is canceled for all the members
                          of the cluster.
        :returns: List of :class:`.Alarm`
        """
        alarm_request = self._build_alarm_request('deactivate',
                                                  member_id,
                                                  'no space')
        alarm_response = self.maintenancestub.Alarm(alarm_request,
                                                    metadata=self._metadata,
                                                    timeout=self.timeout)

        return [Alarm(alarm.alarm, alarm.memberID)
                for alarm in alarm_response.alarms]

    @_handle_errors
    def snapshot(self, file_obj):
        """Take a snapshot of the database.

        :param file_obj: A file-like object to write the database contents in.
        """
        snapshot_request = etcdrpc.SnapshotRequest()
        snapshot_response = self.maintenancestub.Snapshot(snapshot_request)

        for response in snapshot_response:
            file_obj.write(response.blob)


def client(host='localhost', port=2379,
           ca_cert=None, cert_key=None, cert_cert=None, timeout=None):
    """Return an instance of an Etcd3Client."""
    return Etcd3Client(host=host,
                       port=port,
                       ca_cert=ca_cert,
                       cert_key=cert_key,
                       cert_cert=cert_cert,
                       timeout=timeout)
