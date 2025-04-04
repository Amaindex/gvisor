// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"gvisor.dev/gvisor/pkg/context"
)

// contextID is the auth package's type for context.Context.Value keys.
type contextID int

const (
	// CtxCredentials is a Context.Value key for Credentials.
	CtxCredentials contextID = iota

	// CtxThreadGroupID is the current thread group ID when a context represents
	// a task context. The value is represented as an int32.
	CtxThreadGroupID contextID = iota
)

// CredentialsFromContext returns a copy of the Credentials used by ctx, or a
// set of Credentials with no capabilities if ctx does not have Credentials.
func CredentialsFromContext(ctx context.Context) *Credentials {
	if v := ctx.Value(CtxCredentials); v != nil {
		return v.(*Credentials)
	}
	return NewAnonymousCredentials()
}

// CredentialsOrNilFromContext returns a copy of the Credentials used by ctx,
// or nil if ctx does not have Credentials.
func CredentialsOrNilFromContext(ctx context.Context) *Credentials {
	if v := ctx.Value(CtxCredentials); v != nil {
		return v.(*Credentials)
	}
	return nil
}

// ThreadGroupIDFromContext returns the current thread group ID when ctx
// represents a task context.
func ThreadGroupIDFromContext(ctx context.Context) (tgid int32, ok bool) {
	if tgid := ctx.Value(CtxThreadGroupID); tgid != nil {
		return tgid.(int32), true
	}
	return 0, false
}

// ContextWithCredentials returns a copy of ctx carrying creds.
func ContextWithCredentials(ctx context.Context, creds *Credentials) context.Context {
	return &authContext{ctx, creds}
}

type authContext struct {
	context.Context
	creds *Credentials
}

// Value implements context.Context.
func (ac *authContext) Value(key any) any {
	switch key {
	case CtxCredentials:
		return ac.creds
	default:
		return ac.Context.Value(key)
	}
}
