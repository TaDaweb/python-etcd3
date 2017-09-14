class Etcd3Exception(Exception):
    pass


class InvalidArgumentError(Etcd3Exception):
    pass


class PermissionDeniedError(Etcd3Exception):
    pass


class AlreadyExistsError(Etcd3Exception):
    pass


class AbortedError(Etcd3Exception):
    pass


class DeadlineExceededError(Etcd3Exception):
    pass


class UnknownError(Etcd3Exception):
    pass


class UnauthenticatedError(Etcd3Exception):
    pass


class WatchTimedOut(Etcd3Exception):
    pass


class InternalServerError(Etcd3Exception):
    pass


class ConnectionFailedError(Etcd3Exception):
    pass


class ConnectionTimeoutError(Etcd3Exception):
    pass


class PreconditionFailedError(Etcd3Exception):
    pass


class RevisionCompactedError(Etcd3Exception):
    def __init__(self, compacted_revision):
        self.compacted_revision = compacted_revision
        super(RevisionCompactedError, self).__init__()
