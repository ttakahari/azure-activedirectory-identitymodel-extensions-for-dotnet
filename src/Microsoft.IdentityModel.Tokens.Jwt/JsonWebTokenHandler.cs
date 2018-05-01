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
                { JwtRegisteredClaimNames.Alg, signingCredentials.Algorithm },
                { JwtRegisteredClaimNames.Kid, signingCredentials.Key.KeyId },
                { JwtRegisteredClaimNames.Typ, JwtConstants.HeaderType }
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

        private string EncryptToken(string innerJwt, EncryptingCredentials encryptingCredentials)
        {
            var cryptoProviderFactory = encryptingCredentials.CryptoProviderFactory ?? encryptingCredentials.Key.CryptoProviderFactory;

            if (cryptoProviderFactory == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX12733));

            // if direct algorithm, look for support
            if (JwtConstants.DirectKeyUseAlg.Equals(encryptingCredentials.Alg, StringComparison.Ordinal))
            {
                if (!cryptoProviderFactory.IsSupportedAlgorithm(encryptingCredentials.Enc, encryptingCredentials.Key))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10615, encryptingCredentials.Enc, encryptingCredentials.Key)));

                var header = new JObject();
                string outboundAlg;
                if (OutboundAlgorithmMap != null && OutboundAlgorithmMap.TryGetValue(encryptingCredentials.Alg, out outboundAlg))
                    header.Add(JwtRegisteredClaimNames.Alg, outboundAlg);
                else
                    header.Add(JwtRegisteredClaimNames.Alg, encryptingCredentials.Alg);

                if (OutboundAlgorithmMap != null && OutboundAlgorithmMap.TryGetValue(encryptingCredentials.Enc, out outboundAlg))
                    header.Add(JwtRegisteredClaimNames.Enc, outboundAlg);
                else
                    header.Add(JwtRegisteredClaimNames.Enc, encryptingCredentials.Enc);

                if (!string.IsNullOrEmpty(encryptingCredentials.Key.KeyId))
                    header.Add(JwtRegisteredClaimNames.Kid, encryptingCredentials.Key.KeyId);

                header.Add(JwtRegisteredClaimNames.Typ, JwtConstants.HeaderType);

                var encryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(encryptingCredentials.Key, encryptingCredentials.Enc);
                if (encryptionProvider == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX12730));

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
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX12730));

                try
                {
                    var header = new JObject();
                    string outboundAlg;
                    if (OutboundAlgorithmMap != null && OutboundAlgorithmMap.TryGetValue(encryptingCredentials.Alg, out outboundAlg))
                        header.Add(JwtRegisteredClaimNames.Alg, outboundAlg);
                    else
                        header.Add(JwtRegisteredClaimNames.Alg, encryptingCredentials.Alg);

                    if (OutboundAlgorithmMap != null && OutboundAlgorithmMap.TryGetValue(encryptingCredentials.Enc, out outboundAlg))
                        header.Add(JwtRegisteredClaimNames.Enc, outboundAlg);
                    else
                        header.Add(JwtRegisteredClaimNames.Enc, encryptingCredentials.Enc);

                    if (!string.IsNullOrEmpty(encryptingCredentials.Key.KeyId))
                        header.Add(JwtRegisteredClaimNames.Kid, encryptingCredentials.Key.KeyId);

                    header.Add(JwtRegisteredClaimNames.Typ, JwtConstants.HeaderType);

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
        
        // Will probably need to check if we have a signature provider in the cache?
        //public async Task<TokenValidationResult> ValidateJwtAsync(string token, TokenValidationParameters validationParameters)
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
