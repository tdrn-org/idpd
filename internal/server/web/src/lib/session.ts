export type UserVerificationLog = {
    registration: string | null
    last_used: string | null
    host: string | null
    country: string | null
    country_code: string | null
    lat: number | null
    lon: number | null

}

export type UserInfo = {
    name: string
    subject: string
    email: string
    email_verification: UserVerificationLog
    totp_verification: UserVerificationLog
    passkey_verification: UserVerificationLog
    webauthn_verification: UserVerificationLog
}
