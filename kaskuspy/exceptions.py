# -*- coding: utf-8 -*-


class ErrorResponse(Exception):

    def __init__(self, error=None, errorcode=None, errormessage=None,
                 errordetails=None):
        self.error = error
        self.errorcode = errorcode
        self.errormessage = errormessage
        self.errordetails = errordetails

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return (
            "ErrorResponse(error={}, errorcode={}, errormessage={}"
            ", errordetails={})"
        ).format(self.error, self.errorcode, self.errormessage,
                 self.errordetails)
