//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using Newtonsoft.Json.Linq;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.IdentityModel.Logging;

using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens.Jwt
{
    class JsonWebTokenHandler : SecurityTokenHandler
    {
        /// <summary>
        /// Default value to use for the 'typ' claim in the header.
        /// https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public const string JWT = "JWT";

        /// <summary>
        /// Gets the type of the <see cref="JsonWebToken"/>.
        /// </summary>
        /// <return>The type of <see cref="JsonWebToken"/></return>
        public override Type TokenType
        {
            get { return typeof(JsonWebToken); }
        }

        public async Task<string> CreateJWSAsync(JObject payload, SignatureProvider signatureProvider)
        {
            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            if (signatureProvider == null)
                throw new ArgumentNullException(nameof(signatureProvider));

            var header = new JObject
            {
                { JwtRegisteredClaimNames.Alg, signatureProvider.Algorithm },
                { JwtRegisteredClaimNames.Kid, signatureProvider.Key.KeyId },
                { JwtRegisteredClaimNames.Typ, JWT }
            };

            if (signatureProvider.Key is X509SecurityKey x509SecurityKey)
                header.Add(JwtRegisteredClaimNames.X5t, x509SecurityKey.X5t);

            var message = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToString(Newtonsoft.Json.Formatting.None))) + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToString(Newtonsoft.Json.Formatting.None)));
            return message + "." + Base64UrlEncoder.Encode(await signatureProvider.SignAsync(Encoding.UTF8.GetBytes(message)).ConfigureAwait(false));
        }

        //public async Task<TokenValidationResult> ValidateJwtAsync(string token, TokenValidationParameters validationParameters, SignatureProvider signatureProvider)
        //{
        //    if (string.IsNullOrEmpty(token))
        //        throw new ArgumentNullException(nameof(token));

        //    if (validationParameters == null)
        //        throw new ArgumentNullException(nameof(validationParameters));

        //    if (signatureProvider == null)
        //        throw new ArgumentNullException(nameof(signatureProvider));

        //    if (token.Length > MaximumTokenSizeInBytes)
        //        throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

        //    var tokenParts = token.Split(new char[] { '.' }, JwtConstants.MaxJwtSegmentCount + 1);
        //    if (tokenParts.Length != JwtConstants.JwsSegmentCount && tokenParts.Length != JwtConstants.JweSegmentCount)
        //        throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12709, token)));

        //    if (tokenParts.Length == JwtConstants.JweSegmentCount)
        //    {
        //        var jwtToken = new JwtSecurityToken(token);
        //        var decryptedJwt = DecryptToken(jwtToken, validationParameters);
        //        var innerToken = new JwtSecurityToken(decryptedJwt);
        //        var signatureBytes = Base64UrlEncoder.DecodeBytes(innerToken.RawSignature);
        //        var messageBytes = Encoding.UTF8.GetBytes(innerToken.RawHeader + "." + innerToken.RawPayload);
        //        if (!await signatureProvider.VerifyAsync(messageBytes, signatureBytes).ConfigureAwait(false))
        //            throw new TokenValidatorException(LogMessages.S2S32206);
        //        jwtToken.InnerToken = innerToken;

        //        return ValidateTokenInternals(jwtToken, jwtToken.RawData, validationParameters);
        //    } else
        //    {
        //        var jwtToken = new JwtSecurityToken(token);
        //        var signatureBytes = Base64UrlEncoder.DecodeBytes(jwtToken.RawSignature);
        //        var messageBytes = Encoding.UTF8.GetBytes(jwtToken.RawHeader + "." + jwtToken.RawPayload);
        //        if (!await signatureProvider.VerifyAsync(messageBytes, signatureBytes).ConfigureAwait(false))
        //            throw new TokenValidatorException(LogMessages.S2S32206);

        //        return ValidateTokenInternals(jwtToken, jwtToken.RawData, validationParameters);
        //    }
        //}

        //private static TokenValidationResult ValidateTokenInternals(JwtSecurityToken jwtToken, string token, TokenValidationParameters validationParameters)
        //{

        //    Validators.ValidateAudience(jwtToken.Audiences, jwtToken, validationParameters);
        //    var issuer = Validators.ValidateIssuer(jwtToken.Issuer, jwtToken, validationParameters);
        //    Validators.ValidateLifetime(jwtToken.ValidFrom, jwtToken.ValidTo, jwtToken, validationParameters);
        //    Validators.ValidateTokenReplay(token, jwtToken.ValidTo, validationParameters);
        //    Validators.ValidateIssuerSecurityKey(jwtToken.SecurityKey, jwtToken, validationParameters);

        //    return new TokenValidationResult
        //    {
        //        Issuer = issuer,
        //        SecurityToken = jwtToken
        //    };
        //}

        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters)
        {
            throw new NotImplementedException();
        }

        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            throw new NotImplementedException();
        }
    }
}
