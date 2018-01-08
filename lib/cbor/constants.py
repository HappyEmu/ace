class ASInformation:
    AS    = 0
    NONCE = 5


class GrantTypes:
    PASSWORD           = 0
    AUTHORIZATION_CODE = 1
    CLIENT_CREDENTIALS = 2
    REFRESH_TOKEN      = 3


class TokenRequest:
    AUD               = 3
    CLIENT_ID         = 8
    CLIENT_SECRET     = 9
    RESPONSE_TYPE     = 10
    REDIRECT_URI      = 11
    SCOPE             = 12
    STATE             = 13
    CODE              = 14
    ERROR             = 15
    ERROR_DESCRIPTION = 16
    ERROR_URI         = 17
    GRANT_TYPE        = 18
    ACCESS_TOKEN      = 19
    TOKEN_TYPE        = 20
    EXPIRES_IN        = 21
    USERNAME          = 22
    PASSWORD          = 23
    REFRESH_TOKEN     = 24
    CNF               = 25
    PROFILE           = 26
    RS_CNF            = 31


class Cwt:
    ISS = 1
    SUB = 2
    AUD = 3
    EXP = 4
    NBF = 5
    IAT = 6
    CTI = 7


class TokenIntrospection:
    ISS             = 1
    SUB             = 2
    AUD             = 3
    EXP             = 4
    NBF             = 5
    IAT             = 6
    CTI             = 7
    CLIENT_ID       = 8
    SCOPE           = 12
    TOKEN_TYPE      = 20
    USERNAME        = 22
    CNF             = 25
    PROFILE         = 26
    TOKEN           = 27
    TOKEN_TYPE_HINT = 28
    ACTIVE          = 29
    CLIENT_TOKEN    = 30
    RS_CNF          = 31


class ErrorResponse:
    INVALID_REQUEST        = 0     # 4.00 (Bad Request)
    INVALID_CLIENT         = 1     # 4.01 (Unauthorized)
    INVALID_GRANT          = 2     # 4.00 (Bad Request)
    UNAUTHORIZED_CLIENT    = 3     # 4.00 (Bad Request)
    UNSUPPORTED_GRANT_TYPE = 4     # 4.00 (Bad Request)
    INVALID_SCOPE          = 5     # 4.00 (Bad Request)
    UNSUPPORTED_POP_KEY    = 6     # 4.00 (Bad Request)
