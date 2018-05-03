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

using Microsoft.IdentityModel.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens.Jwt
{
    class JsonWebTokenHandler : SecurityTokenHandler
    {
        private JwtTokenUtilities _jwtTokenUtilities = new JwtTokenUtilities();
        private IDictionary<string, string> _outboundAlgorithmMap = null;

        /// <summary>
        /// Default JwtHeader algorithm mapping
        /// </summary>
        public static IDictionary<string, string> DefaultOutboundAlgorithmMap;
     
        /// <summary>
        /// Static initializer for a new object. Static initializers run before the first instance of the type is created.
        /// </summary>
        static JsonWebTokenHandler()
        {
            DefaultOutboundAlgorithmMap = new Dictionary<string, string>
            {
                 { SecurityAlgorithms.EcdsaSha256Signature, SecurityAlgorithms.EcdsaSha256 },
                 { SecurityAlgorithms.EcdsaSha384Signature, SecurityAlgorithms.EcdsaSha384 },
                 { SecurityAlgorithms.EcdsaSha512Signature, SecurityAlgorithms.EcdsaSha512 },
                 { SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.HmacSha256 },
                 { SecurityAlgorithms.HmacSha384Signature, SecurityAlgorithms.HmacSha384 },
                 { SecurityAlgorithms.HmacSha512Signature, SecurityAlgorithms.HmacSha512 },
                 { SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.RsaSha256 },
                 { SecurityAlgorithms.RsaSha384Signature, SecurityAlgorithms.RsaSha384 },
                 { SecurityAlgorithms.RsaSha512Signature, SecurityAlgorithms.RsaSha512 },
            };
        }
        /// <summary>
        /// Gets the type of the <see cref="JsonWebToken"/>.
        /// </summary>
        /// <return>The type of <see cref="JsonWebToken"/></return>
        public override Type TokenType
        {
            get { return typeof(JsonWebToken); }
        }

        public async Task<string> CreateJsonWebTokenAsync(JObject payload, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials)
        {
            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            var header = signingCredentials == null ? new JObject() : new JObject
            {
                { JwtHeaderParameterNames.Alg, signingCredentials.Algorithm },
                { JwtHeaderParameterNames.Kid, signingCredentials.Key.KeyId },
                { JwtHeaderParameterNames.Typ, JwtConstants.HeaderType }
            };

            string rawHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToString(Newtonsoft.Json.Formatting.None)));
            string rawPayload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToString(Newtonsoft.Json.Formatting.None)));
            string rawSignature = signingCredentials == null ? string.Empty : await _jwtTokenUtilities.CreateEncodedSignatureAsync(string.Concat(rawHeader, ".", rawPayload), signingCredentials).ConfigureAwait(false);

            var rawData = rawHeader + "." + rawPayload + "." + rawSignature;

            if (encryptingCredentials != null)
                return EncryptToken(rawData, encryptingCredentials);
            else
                return rawData;
        }

        public async Task<string> CreateJWSAsync(JObject payload, SigningCredentials signingCredentials)
        {
            return await CreateJsonWebTokenAsync(payload, signingCredentials, null).ConfigureAwait(false);
        }

        private string EncryptToken(string innerJwt, EncryptingCredentials encryptingCredentials)
        {
            var cryptoProviderFactory = encryptingCredentials.CryptoProviderFactory ?? encryptingCredentials.Key.CryptoProviderFactory;

            if (cryptoProviderFactory == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX14104));

            // if direct algorithm, look for support
            if (JwtConstants.DirectKeyUseAlg.Equals(encryptingCredentials.Alg, StringComparison.Ordinal))
            {
                if (!cryptoProviderFactory.IsSupportedAlgorithm(encryptingCredentials.Enc, encryptingCredentials.Key))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10615, encryptingCredentials.Enc, encryptingCredentials.Key)));

                var header = new JObject();
                string outboundAlg;
                if (OutboundAlgorithmMap != null && OutboundAlgorithmMap.TryGetValue(encryptingCredentials.Alg, out outboundAlg))
                    header.Add(JwtHeaderParameterNames.Alg, outboundAlg);
                else
                    header.Add(JwtHeaderParameterNames.Alg, encryptingCredentials.Alg);

                if (OutboundAlgorithmMap != null && OutboundAlgorithmMap.TryGetValue(encryptingCredentials.Enc, out outboundAlg))
                    header.Add(JwtHeaderParameterNames.Enc, outboundAlg);
                else
                    header.Add(JwtHeaderParameterNames.Enc, encryptingCredentials.Enc);

                if (!string.IsNullOrEmpty(encryptingCredentials.Key.KeyId))
                    header.Add(JwtHeaderParameterNames.Kid, encryptingCredentials.Key.KeyId);

                header.Add(JwtHeaderParameterNames.Typ, JwtConstants.HeaderType);

                var encryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(encryptingCredentials.Key, encryptingCredentials.Enc);
                if (encryptionProvider == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX14103));

                try
                {
                    var rawHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToString(Newtonsoft.Json.Formatting.None)));
                    var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(innerJwt), Encoding.ASCII.GetBytes(rawHeader));
                    return string.Join(".", rawHeader, string.Empty, Base64UrlEncoder.Encode(encryptionResult.IV), Base64UrlEncoder.Encode(encryptionResult.Ciphertext), Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag));

                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10616, encryptingCredentials.Enc, encryptingCredentials.Key), ex));
                }
            }
            else
            {
                if (!cryptoProviderFactory.IsSupportedAlgorithm(encryptingCredentials.Alg, encryptingCredentials.Key))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10615, encryptingCredentials.Alg, encryptingCredentials.Key)));

                SymmetricSecurityKey symmetricKey = null;

                // only 128, 384 and 512 AesCbcHmac for CEK algorithm
                if (SecurityAlgorithms.Aes128CbcHmacSha256.Equals(encryptingCredentials.Enc, StringComparison.Ordinal))
                    symmetricKey = new SymmetricSecurityKey(JwtTokenUtilities.GenerateKeyBytes(256));
                else if (SecurityAlgorithms.Aes192CbcHmacSha384.Equals(encryptingCredentials.Enc, StringComparison.Ordinal))
                    symmetricKey = new SymmetricSecurityKey(JwtTokenUtilities.GenerateKeyBytes(384));
                else if (SecurityAlgorithms.Aes256CbcHmacSha512.Equals(encryptingCredentials.Enc, StringComparison.Ordinal))
                    symmetricKey = new SymmetricSecurityKey(JwtTokenUtilities.GenerateKeyBytes(512));
                else
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10617, SecurityAlgorithms.Aes128CbcHmacSha256, SecurityAlgorithms.Aes192CbcHmacSha384, SecurityAlgorithms.Aes256CbcHmacSha512, encryptingCredentials.Enc)));

                var kwProvider = cryptoProviderFactory.CreateKeyWrapProvider(encryptingCredentials.Key, encryptingCredentials.Alg);
                var wrappedKey = kwProvider.WrapKey(symmetricKey.Key);
                var encryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(symmetricKey, encryptingCredentials.Enc);
                if (encryptionProvider == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX14103));

                try
                {
                    var header = new JObject();
                    string outboundAlg;
                    if (OutboundAlgorithmMap != null && OutboundAlgorithmMap.TryGetValue(encryptingCredentials.Alg, out outboundAlg))
                        header.Add(JwtHeaderParameterNames.Alg, outboundAlg);
                    else
                        header.Add(JwtHeaderParameterNames.Alg, encryptingCredentials.Alg);

                    if (OutboundAlgorithmMap != null && OutboundAlgorithmMap.TryGetValue(encryptingCredentials.Enc, out outboundAlg))
                        header.Add(JwtHeaderParameterNames.Enc, outboundAlg);
                    else
                        header.Add(JwtHeaderParameterNames.Enc, encryptingCredentials.Enc);

                    if (!string.IsNullOrEmpty(encryptingCredentials.Key.KeyId))
                        header.Add(JwtHeaderParameterNames.Kid, encryptingCredentials.Key.KeyId);

                    header.Add(JwtHeaderParameterNames.Typ, JwtConstants.HeaderType);

                    var rawHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToString(Newtonsoft.Json.Formatting.None)));
                    var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(innerJwt), Encoding.ASCII.GetBytes(rawHeader));
                    return string.Join(".", rawHeader, Base64UrlEncoder.Encode(wrappedKey), Base64UrlEncoder.Encode(encryptionResult.IV), Base64UrlEncoder.Encode(encryptionResult.Ciphertext), Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag));
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10616, encryptingCredentials.Enc, encryptingCredentials.Key), ex));
                }
            }
        }

        /// <summary>
        /// Gets the outbound algorithm map that is used to form the header.
        /// </summary>
        public IDictionary<string, string> OutboundAlgorithmMap
        {
            get
            {
                return _outboundAlgorithmMap;
            }
        }

        public async Task<TokenValidationResult> ValidateJWSAsync(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentNullException(nameof(token));

            if (validationParameters == null)
                throw new ArgumentNullException(nameof(validationParameters));

            if (token.Length > MaximumTokenSizeInBytes)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

            var validatedJsonWebToken = await ValidateSignatureAsync(token, validationParameters).ConfigureAwait(false);

            return await ValidateTokenPayloadAsync(validatedJsonWebToken as JsonWebToken, validationParameters).ConfigureAwait(false);
        }

        /// <summary>
        /// Validates that the signature, if found or required, is valid.
        /// </summary>
        public async Task<JsonWebToken> ValidateSignatureAsync(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.SignatureValidator != null)
            {
                var validatedToken = validationParameters.SignatureValidator(token, validationParameters);
                if (validatedToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10505, token)));

                var validatedJsonWebToken = validatedToken as JsonWebToken;
                if (validatedJsonWebToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10506, typeof(JsonWebToken), validatedJsonWebToken.GetType(), token)));

                return validatedJsonWebToken;
            }

            JsonWebToken jwtToken = null;

            if (validationParameters.TokenReader != null)
            {
                var securityToken = validationParameters.TokenReader(token, validationParameters);
                if (securityToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10510, token)));

                jwtToken = securityToken as JsonWebToken;
                if (jwtToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10509, typeof(JsonWebToken), securityToken.GetType(), token)));
            }
            else
            {
                jwtToken = new JsonWebToken(token);
            }

            byte[] encodedBytes = Encoding.UTF8.GetBytes(jwtToken.RawHeader + "." + jwtToken.RawPayload);
            if (string.IsNullOrEmpty(jwtToken.RawSignature))
            {
                if (validationParameters.RequireSignedTokens)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10504, token)));
                else
                    return jwtToken;
            }

            bool keyMatched = false;
            IEnumerable<SecurityKey> keys = null;
            if (validationParameters.IssuerSigningKeyResolver != null)
            {
                keys = validationParameters.IssuerSigningKeyResolver(token, jwtToken, jwtToken.Kid, validationParameters);
            }
            else
            {
                var key = ResolveIssuerSigningKey(token, jwtToken, validationParameters);
                if (key != null)
                {
                    keyMatched = true;
                    keys = new List<SecurityKey> { key };
                }
            }

            if (keys == null)
            {
                // control gets here if:
                // 1. User specified delegate: IssuerSigningKeyResolver returned null
                // 2. ResolveIssuerSigningKey returned null
                // Try all the keys. This is the degenerate case, not concerned about perf.
                keys = GetAllSigningKeys(token, validationParameters);
            }

            // keep track of exceptions thrown, keys that were tried
            var exceptionStrings = new StringBuilder();
            var keysAttempted = new StringBuilder();
            bool canMatchKey = !string.IsNullOrEmpty(jwtToken.Kid);
            byte[] signatureBytes;

            try
            {
                signatureBytes = Base64UrlEncoder.DecodeBytes(jwtToken.RawSignature);
            }
            catch (FormatException e)
            {
                throw new SecurityTokenInvalidSignatureException(TokenLogMessages.IDX10508, e);
            }

            foreach (var key in keys)
            {
                try
                {
                    if (await ValidateSignatureAsync(encodedBytes, signatureBytes, key, jwtToken.Alg, validationParameters).ConfigureAwait(false))
                    {
                        LogHelper.LogInformation(TokenLogMessages.IDX10242, token);
                        jwtToken.SigningKey = key;
                        return jwtToken;
                    }
                }
                catch (Exception ex)
                {
                    exceptionStrings.AppendLine(ex.ToString());
                }

                if (key != null)
                {
                    keysAttempted.AppendLine(key.ToString() + " , KeyId: " + key.KeyId);
                    if (canMatchKey && !keyMatched && key.KeyId != null)
                        keyMatched = jwtToken.Kid.Equals(key.KeyId, StringComparison.Ordinal);
                }
            }

            // if the kid != null and the signature fails, throw SecurityTokenSignatureKeyNotFoundException
            if (!keyMatched && canMatchKey && keysAttempted.Length > 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(LogHelper.FormatInvariant(TokenLogMessages.IDX10501, jwtToken.Kid, jwtToken)));

            if (keysAttempted.Length > 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10503, keysAttempted, exceptionStrings, jwtToken)));

            throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(TokenLogMessages.IDX10500));
        }

        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use when validating the signature of a token.
        /// </summary>
        /// <param name="token">The <see cref="string"/> representation of the token that is being validated.</param>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> that is being validated.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/>  required for validation.</param>
        /// <returns>Returns a <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <remarks>If key fails to resolve, then null is returned</remarks>
        protected virtual SecurityKey ResolveIssuerSigningKey(string token, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (jwtToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtToken));

            if (!string.IsNullOrEmpty(jwtToken.Kid))
            {
                string kid = jwtToken.Kid;
                if (validationParameters.IssuerSigningKey != null && string.Equals(validationParameters.IssuerSigningKey.KeyId, kid, StringComparison.Ordinal))
                    return validationParameters.IssuerSigningKey;

                if (validationParameters.IssuerSigningKeys != null)
                {
                    foreach (SecurityKey signingKey in validationParameters.IssuerSigningKeys)
                    {
                        if (signingKey != null && string.Equals(signingKey.KeyId, kid, StringComparison.Ordinal))
                        {
                            return signingKey;
                        }
                    }
                }
            }

            if (!string.IsNullOrEmpty(jwtToken.X5t))
            {
                string x5t = jwtToken.X5t;
                if (validationParameters.IssuerSigningKey != null)
                {
                    if (string.Equals(validationParameters.IssuerSigningKey.KeyId, x5t, StringComparison.Ordinal))
                        return validationParameters.IssuerSigningKey;

                    X509SecurityKey x509Key = validationParameters.IssuerSigningKey as X509SecurityKey;
                    if (x509Key != null && string.Equals(x509Key.X5t, x5t, StringComparison.Ordinal))
                        return validationParameters.IssuerSigningKey;
                }

                if (validationParameters.IssuerSigningKeys != null)
                {
                    foreach (SecurityKey signingKey in validationParameters.IssuerSigningKeys)
                    {
                        if (signingKey != null && string.Equals(signingKey.KeyId, x5t, StringComparison.Ordinal))
                        {
                            return signingKey;
                        }
                    }
                }
            }

            return null;
        }

        private IEnumerable<SecurityKey> GetAllSigningKeys(string token, TokenValidationParameters validationParameters)
        {
            LogHelper.LogInformation(TokenLogMessages.IDX10243);
            if (validationParameters.IssuerSigningKey != null)
                yield return validationParameters.IssuerSigningKey;

            if (validationParameters.IssuerSigningKeys != null)
                foreach (SecurityKey key in validationParameters.IssuerSigningKeys)
                    yield return key;
        }

        /// <summary>
        /// Obtains a <see cref="SignatureProvider "/> and validates the signature.
        /// </summary>
        /// <param name="encodedBytes">Bytes to validate.</param>
        /// <param name="signature">Signature to compare against.</param>
        /// <param name="key"><See cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">Crypto algorithm to use.</param>
        /// <param name="validationParameters">Priority will be given to <see cref="TokenValidationParameters.CryptoProviderFactory"/> over <see cref="SecurityKey.CryptoProviderFactory"/>.</param>
        /// <returns>'true' if signature is valid.</returns>
        private async Task<bool> ValidateSignatureAsync(byte[] encodedBytes, byte[] signature, SecurityKey key, string algorithm, TokenValidationParameters validationParameters)
        {
            var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
            if (!cryptoProviderFactory.IsSupportedAlgorithm(algorithm, key))
            {
                LogHelper.LogInformation(LogMessages.IDX14000, algorithm, key);
                return false;
            }

            var signatureProvider = cryptoProviderFactory.CreateForVerifying(key, algorithm);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(TokenLogMessages.IDX10647, (key == null ? "Null" : key.ToString()), (algorithm == null ? "Null" : algorithm))));

            try
            {
                return await signatureProvider.VerifyAsync(encodedBytes, signature).ConfigureAwait(false);
            }
            finally
            {
                cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        private async Task<TokenValidationResult> ValidateTokenPayloadAsync(JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {

            DateTime? expires = (jwtToken.ValidTo == null) ? null : new DateTime?(jwtToken.ValidTo);
            DateTime? notBefore = (jwtToken.ValidFrom == null) ? null : new DateTime?(jwtToken.ValidFrom);

            Validators.ValidateLifetime(notBefore, expires, jwtToken, validationParameters);
            Validators.ValidateAudience(jwtToken.Audiences, jwtToken, validationParameters);
            string issuer = Validators.ValidateIssuer(jwtToken.Issuer, jwtToken, validationParameters);
            Validators.ValidateTokenReplay(expires, jwtToken.RawData, validationParameters);
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jwtToken.Actor))
            {
                var actorValidationResult = await ValidateJWSAsync(jwtToken.Actor, validationParameters.ActorValidationParameters ?? validationParameters).ConfigureAwait(false);
            }

            Validators.ValidateIssuerSecurityKey(jwtToken.SigningKey, jwtToken, validationParameters);

            return new TokenValidationResult
            {
                SecurityToken = jwtToken
            };
        }

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
