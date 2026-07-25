export interface SessionInfo {
  user: string;
  handler: string;
}

export interface LoginRequest {
  handler: string;
  username: string;
  password: string;
  otp?: string;
}
