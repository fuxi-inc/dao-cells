/*
 * Copyright (c) 2021. Abstrium SAS <team (at) pydio.com>
 * This file is part of Pydio Cells.
 *
 * Pydio Cells is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pydio Cells is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Pydio Cells.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The latest code can be found at <https://pydio.com>.
 */

package modifiers

import (
	"context"
	"github.com/fuxi-inc/dip-common-lib/IDL"
	"github.com/pydio/cells/v4/dip"
	"net/url"
	"strconv"
	"strings"

	restful "github.com/emicklei/go-restful/v3"
	"github.com/gorilla/sessions"

	"github.com/pydio/cells/v4/common/auth"
	"github.com/pydio/cells/v4/common/auth/hydra"
	pauth "github.com/pydio/cells/v4/common/proto/auth"
	"github.com/pydio/cells/v4/common/proto/rest"
	"github.com/pydio/cells/v4/common/service/frontend"
)

func LoginPasswordAuth(middleware frontend.AuthMiddleware) frontend.AuthMiddleware {
	return func(req *restful.Request, rsp *restful.Response, in *frontend.FrontSessionWithRuntimeCtx, out *rest.FrontSessionResponse, session *sessions.Session) error {
		if a, ok := in.AuthInfo["type"]; !ok || a != "credentials" { // Ignore this middleware
			return middleware(req, rsp, in, out, session)
		}

		username := in.AuthInfo["login"]
		password := in.AuthInfo["password"]

		if challenge, ok := in.AuthInfo["challenge"]; ok {
			// If we do have a challenge, then we're coming from an external source and
			code, err := auth.DefaultJWTVerifier().PasswordCredentialsCode(req.Request.Context(), username, password, auth.SetChallenge(challenge))
			if err != nil {
				return err
			}

			login, err := hydra.GetLogin(req.Request.Context(), challenge)
			if err != nil {
				return err
			}
			requestURL, err := url.Parse(login.GetRequestURL())
			if err != nil {
				return err
			}

			requestURLValues := requestURL.Query()

			redirectURL, err := auth.GetRedirectURIFromRequestValues(requestURLValues)
			if err != nil {
				return err
			}

			out.RedirectTo = redirectURL + "?code=" + code + "&state=" + requestURLValues.Get("state")
			session.Values["redirect_valid_username"] = username
			session.Values["redirect_final_to"] = out.RedirectTo

			return middleware(req, rsp, in, out, session)
		}

		// If we don't have a challenge then we proceed with a normal login
		token, err := auth.DefaultJWTVerifier().PasswordCredentialsToken(req.Request.Context(), username, password)
		if err != nil {
			return err
		}

		if username != "admin" {
			// DIP, 验证用户公私钥
			publicKey, err := dip.GetPublicKey(context.Background(), strings.Trim(username, ".")+".")
			if err != nil {
				return err
			}

			//todo debug
			//signatureData := IDL.SignatureData{
			//	OperatorDoi:    in.AuthInfo["operator"],
			//	SignatureNonce: in.AuthInfo["nonce"],
			//	Signature:      in.AuthInfo["signature"],
			//}
			signatureData := IDL.SignatureData{
				OperatorDoi:    "mpd635zki3.viv.cn.",
				SignatureNonce: "2qe365kpet",
				Signature:      "9ca63e144f2df19200fc6671fd29e8b3dfdfe9db44dce5e54ca8e7bd71b1f8eee32e7832e7ed72e2b42a6f09a11977dce70923bbcfd333ddb5b2478c2b841f5a9076440938d73e12a5bbbc830667288cd8970bc50d6bb0e193f0511e05158182d15ece556ba846ffc974deb84b05e868440c4c7bf1ff5e3daf2447654dd8b5b3d3baea85bac16385cc7a2f91e37107c1ed6b5f9f9450cf89f39d1df3bdb88d055181798e09bb2f34e44ef5dff04976a1f763e2b8921b8f526e76943f61e844e3a611dbef0dbac6a6e3444eb76e807040f5de2dd3875e26fbb818158c6354585094d6e4db9eebe341c76aeba0c8e80fd26041e561e718bcace166c4e111771c00",
			}
			err = signatureData.VerifySignature(publicKey)
			if err != nil {
				return err
			}
		}

		_, claims, err := auth.DefaultJWTVerifier().Verify(req.Request.Context(), token.AccessToken)
		if err != nil {
			return err
		}

		in.AuthInfo["source"] = claims.AuthSource

		session.Values["access_token"] = token.AccessToken
		session.Values["id_token"] = token.Extra("id_token").(string)
		session.Values["expires_at"] = strconv.Itoa(int(token.Expiry.Unix()))
		session.Values["refresh_token"] = token.RefreshToken

		out.Token = &pauth.Token{
			AccessToken: session.Values["access_token"].(string),
			IDToken:     session.Values["id_token"].(string),
			ExpiresAt:   session.Values["expires_at"].(string),
		}

		return middleware(req, rsp, in, out, session)
	}
}
