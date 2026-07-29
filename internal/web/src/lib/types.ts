export interface SessionInfo {
  strong_auth: boolean;
  user: UserInfo;
}

export interface UserInfo {
  login: string;
  name: string;
  nickname: string;
  picture: string;
  email: string;
  groups: string[];
}

export interface SessionLoginInfo {
  login_hint: string;
  remember: boolean;
  allowed_verifications: string[];
}

export interface SessionLoginRequest {
  login: string;
  password: string;
  remember: boolean;
  verification: string;
}

export interface SessionVerifyInfo {
  verification: string;
}

export interface SessionVerifyRequest {
  response: string;
}
