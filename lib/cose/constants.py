class Tag:
    COSE_SIGN     = 98
    COSE_SIGN1    = 18
    COSE_ENCRYPT  = 96
    COSE_ENCRYPT0 = 16
    COSE_MAC      = 97
    COSE_MAC0     = 17


class Header:
    ALG = 1  # int / tstr
    CRIT = 2
    CONTENT_TYPE = 3  # tstr / uint
    KID = 4  # bstr
    IV = 5  # bstr
    PARTIAL_IV = 6  # bstr
    COUNTER_SIGNATURE = 7  # COSE_Signature


class Algorithm:
    ES256 = -7
    ES384 = -35
    ES512 = -36
    AES_CCM_16_64_128 = 10
    AES_CCM_64_64_128 = 12


class Key:
    KTY = 1  # tstr
    KID = 2  # bstr
    ALG = 3  # tstr / int
    KEY_OPS = 4  # [(tstr/int)]
    BASE_IV = 5  # bstr

    CRV = -1
    X = -2
    Y = -3
    D = -4

    COSE_KEY = 1
    ENCRYPTED_COSE_KEY = 2

    class Op:
        SIGN = 1
        VERIFY = 2
        ENCRYPT = 3
        DECRYPT = 4

    class Type:
        OKP = 1
        EC2 = 2
        SYMMETRIC = 4

    class Curve:
        P_256 = 1
        P_384 = 2
        P_521 = 3
        X25519 = 4
        X448 = 5
        Ed25519 = 6
        Ed449 = 7
