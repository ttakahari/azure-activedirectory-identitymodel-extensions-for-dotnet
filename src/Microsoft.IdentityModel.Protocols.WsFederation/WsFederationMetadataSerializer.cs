﻿//------------------------------------------------------------------------------
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

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using static Microsoft.IdentityModel.Logging.IdentityModelEventSource;
using static Microsoft.IdentityModel.Protocols.WsFederation.WsFederationConstants;

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    /// Metadata serializer class for WsFed. 
    /// </summary>
    public class WsFederationMetadataSerializer
    {

        private DSigSerializer _dsigSerializer = new DSigSerializer();

        /// <summary>
        /// Metadata serializer for WsFed.
        /// </summary>
        public WsFederationMetadataSerializer() { }

        /// <summary>
        /// Read metadata and create the corresponding WsFed configuration.
        /// </summary>
        /// <param name="reader">xml reader</param>
        /// <returns>WsFed configuration</returns>
        public WsFederationConfiguration ReadMetadata(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.EntityDescriptor, Namespaces.MetadataNamespace);

            var envelopeReader = new EnvelopedSignatureReader(XmlDictionaryReader.CreateDictionaryReader(reader));

            try
            {
                var configuration = ReadEntityDescriptor(envelopeReader);
                configuration.Signature = envelopeReader.Signature;
                return configuration;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX13000, ex, Elements.EntityDescriptor, ex);
            }
        }

        /// <summary>
        /// Read EntityDescriptor element in xml.
        /// </summary>
        /// <param name="reader">xmlreader</param>
        /// <returns>Wsfed configuration</returns>
        protected virtual WsFederationConfiguration ReadEntityDescriptor(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.EntityDescriptor, Namespaces.MetadataNamespace);

            var configuration = new WsFederationConfiguration();

            // get entityID for issuer
            configuration.Issuer = reader.GetAttribute(Attributes.EntityId);

            if (string.IsNullOrEmpty(configuration.Issuer))
                throw XmlUtil.LogReadException(LogMessages.IDX13001);

            // <EntityDescriptor>
            reader.ReadStartElement();

            // flag for the existence of SecurityTokenSeviceType RoleDescriptor
            var hasSecurityTokenServiceTypeRoleDescriptor = false;

            while (reader.IsStartElement())
            {
                if (IsSecurityTokenServiceTypeRoleDescriptor(reader))
                {
                    hasSecurityTokenServiceTypeRoleDescriptor = true;
                    var roleDescriptor = ReadSecurityTokenServiceTypeRoleDescriptor(reader);
                    foreach(var keyInfo in roleDescriptor.KeyInfos)
                    {
                        configuration.KeyInfos.Add(keyInfo);
                        if (!string.IsNullOrEmpty(keyInfo.CertificateData))
                        {
                            var cert = new X509Certificate2(Convert.FromBase64String(keyInfo.CertificateData));
                            configuration.SigningKeys.Add(new X509SecurityKey(cert));
                        }
                    }
                    configuration.TokenEndpoint = roleDescriptor.TokenEndpoint;
                }
                else
                {
                    reader.ReadOuterXml();
                }
            }

            // </EntityDescriptor>
            reader.ReadEndElement();

            // The metadata xml should contain a SecurityTokenServiceType RoleDescriptor
            if (!hasSecurityTokenServiceTypeRoleDescriptor)
                throw XmlUtil.LogReadException(LogMessages.IDX13004);

            return configuration;
        }

        /// <summary>
        /// Read KeyDescriptor element in xml.
        /// </summary>
        /// <param name="reader">xmlreader</param>
        /// <returns>key info</returns>
        protected virtual KeyInfo ReadKeyDescriptorForSigning(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.KeyDescriptor, Namespaces.MetadataNamespace);

            var use = reader.GetAttribute(Attributes.Use);
            if (string.IsNullOrEmpty(use))
                Logger.WriteWarning(LogMessages.IDX13008);
            else if (!use.Equals(keyUse.Signing))
                throw XmlUtil.LogReadException(LogMessages.IDX13009, Attributes.Use, keyUse.Signing, use);

            // <KeyDescriptor>
            reader.ReadStartElement();

            KeyInfo keyInfo = null;

            if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
                keyInfo = _dsigSerializer.ReadKeyInfo(reader);
            else
                throw XmlUtil.LogReadException(LogMessages.IDX13002, reader.LocalName, reader.NamespaceURI, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);

            // </KeyDescriptor>
            reader.ReadEndElement();

            if (keyInfo == null)
                throw XmlUtil.LogReadException(LogMessages.IDX13010);

            return keyInfo;
        }

        /// <summary>
        /// Read RoleDescriptor element in xml.
        /// </summary>
        /// <param name="reader">xmlreader</param>
        /// <returns>Security token service type role descriptor</returns>
        protected virtual SecurityTokenServiceTypeRoleDescriptor ReadSecurityTokenServiceTypeRoleDescriptor(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.RoleDescriptor, Namespaces.MetadataNamespace);

            if (!IsSecurityTokenServiceTypeRoleDescriptor(reader))
                throw XmlUtil.LogReadException(LogMessages.IDX13004);

            var roleDescriptor = new SecurityTokenServiceTypeRoleDescriptor();

            // <RoleDescriptorr>
            reader.ReadStartElement();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(Elements.KeyDescriptor, Namespaces.MetadataNamespace) && reader.GetAttribute(Attributes.Use).Equals(keyUse.Signing))
                    roleDescriptor.KeyInfos.Add(ReadKeyDescriptorForSigning(reader));
                else if (reader.IsStartElement(Elements.SecurityTokenEndpoint, Namespaces.FederationNamespace))
                    roleDescriptor.TokenEndpoint = ReadSecurityTokenEndpoint(reader);
                else if (reader.IsStartElement())
                    reader.ReadOuterXml();
                else
                    throw XmlUtil.LogReadException(LogMessages.IDX13003, reader.Name);
            }

            // </RoleDescriptorr>
            reader.ReadEndElement();

            if (roleDescriptor.KeyInfos.Count == 0)
                Logger.WriteWarning(LogMessages.IDX13006);

            if (string.IsNullOrEmpty(roleDescriptor.TokenEndpoint))
                Logger.WriteWarning(LogMessages.IDX13007);

            return roleDescriptor;
        }

        /// <summary>
        /// Read fed:SecurityTokenServiceEndpoint element in xml.
        /// </summary>
        /// <param name="reader">xmlreader</param>
        /// <returns>token endpoint string</returns>
        protected virtual string ReadSecurityTokenEndpoint(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.SecurityTokenEndpoint, Namespaces.FederationNamespace);

            // <SecurityTokenServiceEndpoint>
            reader.ReadStartElement();
            reader.MoveToContent();

            XmlUtil.CheckReaderOnEntry(reader, Elements.EndpointReference, Namespaces.AddressingNamspace);
            reader.ReadStartElement(Elements.EndpointReference, Namespaces.AddressingNamspace);  // EndpointReference
            reader.MoveToContent();

            XmlUtil.CheckReaderOnEntry(reader, Elements.Address, Namespaces.AddressingNamspace);
            reader.ReadStartElement(Elements.Address, Namespaces.AddressingNamspace);  // Address
            reader.MoveToContent();

            var tokenEndpoint = Trim(reader.ReadContentAsString());

            if (string.IsNullOrEmpty(tokenEndpoint))
                throw XmlUtil.LogReadException(LogMessages.IDX13003);

            // </Address>
            reader.MoveToContent();
            reader.ReadEndElement();

            // </EndpointReference>
            reader.MoveToContent();
            reader.ReadEndElement();

            // </SecurityTokenServiceEndpoint>
            reader.MoveToContent();
            reader.ReadEndElement();

            return tokenEndpoint;
        }

        private bool IsSecurityTokenServiceTypeRoleDescriptor(XmlReader reader)
        {
            if (reader == null || !reader.IsStartElement(Elements.RoleDescriptor, Namespaces.MetadataNamespace))
                return false;

            var type = reader.GetAttribute(Attributes.Type, XmlSignatureConstants.XmlSchemaNamespace);
            var typeQualifiedName = new XmlQualifiedName();

            if (!string.IsNullOrEmpty(type))
                typeQualifiedName = XmlUtil.ResolveQName(reader, type);

            if (!XmlUtil.EqualsQName(typeQualifiedName, Types.SecurityTokenServiceType, Namespaces.FederationNamespace))
                return false;

            return true;
        }

        internal static string Trim(string stringToTrim)
        {
            if (string.IsNullOrEmpty(stringToTrim))
                return stringToTrim;

            char[] charsToTrim = { ' ', '\n' };
            return stringToTrim.Trim(charsToTrim);
        }
    }

    /// <summary>
    /// Class for SecurityTokenService type role descriptor
    /// </summary>
    public class SecurityTokenServiceTypeRoleDescriptor
    {
        /// <summary>
        /// KeyInfo
        /// </summary>
        public List<KeyInfo> KeyInfos
        {
            get;
            set;
        } = new List<KeyInfo>();

        /// <summary>
        /// Token endpoint
        /// </summary>
        public string TokenEndpoint
        {
            get;
            set;
        } = null;
    }
}
