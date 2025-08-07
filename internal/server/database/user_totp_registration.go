/*
 * Copyright 2025 Holger de Carne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package database

import "time"

type UserTOTPRegistrationRequest struct {
	Subject    string
	Secret     string
	Challenge  string
	Expiration int64
}

func NewUserTOTPRegistrationRequest(subject string, secret string, challenge string) *UserTOTPRegistrationRequest {
	return &UserTOTPRegistrationRequest{
		Subject:    subject,
		Secret:     secret,
		Challenge:  challenge,
		Expiration: time.Now().Add(5 * time.Minute).UnixMicro(),
	}
}

type UserTOTPRegistration struct {
	Subject    string
	Secret     string
	CreateTime int64
}

func NewUserTOTPRegistrationFromRequest(request *UserTOTPRegistrationRequest) *UserTOTPRegistration {
	return &UserTOTPRegistration{
		Subject:    request.Subject,
		Secret:     request.Secret,
		CreateTime: time.Now().UnixMicro(),
	}
}
