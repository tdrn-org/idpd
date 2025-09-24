import { goto } from "$app/navigation"

export type UserInfo = {
    name: string
    subject: string
    email: string
    email_verification: UserVerificationLog
    totp_verification: UserVerificationLog
    passkey_verification: UserVerificationLog
    webauthn_verification: UserVerificationLog
}

export type UserVerificationLog = {
    registration: string | null
    last_used: string | null
    host: string | null
    country: string | null
    country_code: string | null
    city: string | null
    lat: number | null
    lon: number | null
}

export type UserTOTPRegistrationRequest = {
    qr_code: string
    otp_url: string
}

async function fetchUserInfo(id: string | null): Promise<UserInfo> {
    let url: string = `/session`;
    if (id) {
        url += new URLSearchParams({id: id})
    }
    const response = await fetch(url);
    const userInfo: UserInfo = await response.json();
    return userInfo;
}

	function restartLogin() {
		goto('/authenticate');
	}

const session = {
    restartLogin,
    fetchUserInfo,
}

export default session;