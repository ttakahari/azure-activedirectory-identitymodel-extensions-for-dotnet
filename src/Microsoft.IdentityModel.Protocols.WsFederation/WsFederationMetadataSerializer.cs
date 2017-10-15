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

using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using static Microsoft.IdentityModel.Logging.IdentityModelEventSource;
using static Microsoft.IdentityModel.Logging.LogHelper;
using static Microsoft.IdentityModel.Protocols.WsFederation.WsFederationConstants;

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    /// Metadata serializer class for WsFed. 
    /// </summary>
    public class WsFederationMetadataSerializer
    {

        private DSigSerializer _dsigSerializer = DSigSerializer.Default;

        /// <summary>
        /// Metadata serializer for WsFed.
        /// </summary>
        public WsFederationMetadataSerializer() { }

#region Read Metadata

        /// <summary>
        /// Read metadata and create the corresponding <see cref="WsFederationConfiguration"/>.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read metadata</param>
        /// <returns><see cref="WsFederationConfiguration"/></returns>
        /// <exception cref="XmlReadException">if error occurs when reading metadata</exception>
        public WsFederationConfiguration ReadMetadata(XmlReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            var envelopeReader = new EnvelopedSignatureReader(reader);

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

                throw XmlUtil.LogReadException(LogMessages.IDX22800, ex, Elements.EntityDescriptor, ex);
            }
        }

        /// <summary>
        /// Read EntityDescriptor element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read entity descriptor</param>
        /// <returns><see cref="WsFederationConfiguration"/></returns>
        /// <exception cref="XmlReadException">if error occurs when reading entity descriptor</exception>
        protected virtual WsFederationConfiguration ReadEntityDescriptor(XmlReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            // check invalid or empty <EntityDescriptor>
            var invalidOrEmptyElement = HandleIncorrectAndEmptyElement<WsFederationConfiguration>(reader, Elements.EntityDescriptor);
            if (invalidOrEmptyElement.Exists)
                return invalidOrEmptyElement.ResultObject; // we cannot simply return a new WsFederationConfiguration instance, since an empty element can have issuer.

            var configuration = new WsFederationConfiguration();

            // get entityID for issuer
            var issuer = reader.GetAttribute(Attributes.EntityId);
            if (string.IsNullOrEmpty(issuer))
                Logger.WriteWarning(LogMessages.IDX22801);
            configuration.Issuer = issuer;

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
                        if (keyInfo.X509Data != null)
                        {
                            foreach (var data in keyInfo.X509Data)
                            {
                                foreach (var certificate in data.Certificates)
                                {
                                    var cert = new X509Certificate2(Convert.FromBase64String(certificate));
                                    configuration.SigningKeys.Add(new X509SecurityKey(cert));
                                }
                            }
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
                Logger.WriteWarning(LogMessages.IDX22804);

            return configuration;
        }

        /// <summary>
        /// Read KeyDescriptor element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read key descriptor</param>
        /// <returns><see cref="KeyInfo"/></returns>
        /// <exception cref="XmlReadException">if error occurs when reading key descriptor</exception>
        protected virtual KeyInfo ReadKeyDescriptorForSigning(XmlReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            // check invalid or empty <KeyDescriptor>
            var invalidOrEmptyElement = HandleIncorrectAndEmptyElement<KeyInfo>(reader, Elements.KeyDescriptor);
            if (invalidOrEmptyElement.Exists)
                return invalidOrEmptyElement.ResultObject;

            var keyInfo = new KeyInfo();
            
            // <KeyDescriptor>
            reader.ReadStartElement();

            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, ElementNamespacePair[XmlSignatureConstants.Elements.KeyInfo]))
                    keyInfo = _dsigSerializer.ReadKeyInfo(reader);
                else
                    reader.ReadOuterXml();
            }

            // </KeyDescriptor>
            reader.ReadEndElement();

            return keyInfo;
        }

        /// <summary>
        /// Read RoleDescriptor element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read security token service type role descriptor</param>
        /// <returns><see cref="SecurityTokenServiceTypeRoleDescriptor"/></returns>
        /// <exception cref="XmlReadException">if error occurs when reading role descriptor</exception>
        protected virtual SecurityTokenServiceTypeRoleDescriptor ReadSecurityTokenServiceTypeRoleDescriptor(XmlReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            var roleDescriptor = new SecurityTokenServiceTypeRoleDescriptor();

            // check invalid or empty <RoleDescriptor>
            var invalidOrEmptyElement = HandleIncorrectAndEmptyElement<SecurityTokenServiceTypeRoleDescriptor>(reader, Elements.RoleDescriptor);
            if (invalidOrEmptyElement.Exists)
                return roleDescriptor;           

            // <RoleDescriptor>
            reader.ReadStartElement();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(Elements.KeyDescriptor, ElementNamespacePair[Elements.KeyDescriptor]) && keyUse.Signing.Equals(reader.GetAttribute(Attributes.Use)))
                    roleDescriptor.KeyInfos.Add(ReadKeyDescriptorForSigning(reader));
                else if (reader.IsStartElement(Elements.PassiveRequestorEndpoint, ElementNamespacePair[Elements.PassiveRequestorEndpoint]))
                    roleDescriptor.TokenEndpoint = ReadPassiveRequestorEndpoint(reader);
                else
                    reader.ReadOuterXml();
            }

            // </RoleDescriptor>
            reader.ReadEndElement();

            if (roleDescriptor.KeyInfos.Count == 0)
                Logger.WriteWarning(LogMessages.IDX22806);

            if (string.IsNullOrEmpty(roleDescriptor.TokenEndpoint))
                Logger.WriteWarning(LogMessages.IDX22807);

            return roleDescriptor;
        }

        /// <summary>
        /// Read fed:PassiveRequestorEndpoint element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read PassiveRequestorEndpoint</param>
        /// <returns>token endpoint string</returns>
        /// <exception cref="XmlReadException">if error occurs when reading PassiveRequestorEndpoint</exception>
        protected virtual string ReadPassiveRequestorEndpoint(XmlReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            // check invalid or empty <PassiveRequestorEndpoint>
            var invalidOrEmptyElement = HandleIncorrectAndEmptyElement<string>(reader, Elements.PassiveRequestorEndpoint);
            if (invalidOrEmptyElement.Exists)
                return null;

            string tokenEndpoint = null;

            // <PassiveRequestorEndpoint>
            reader.ReadStartElement();
            reader.MoveToContent();

            while (reader.IsStartElement())
            {
                if(reader.IsStartElement(Elements.EndpointReference, ElementNamespacePair[Elements.EndpointReference]))
                {
                    // check invalid or empty <EndpointReference>
                    var invalidOrEmptyElementForEndpointReference = HandleIncorrectAndEmptyElement<string>(reader, Elements.EndpointReference);
                    if (invalidOrEmptyElementForEndpointReference.Exists)
                        continue;

                    // <EndpointReference>
                    reader.ReadStartElement();
                    reader.MoveToContent();

                    while (reader.IsStartElement())
                    {
                        if (reader.IsStartElement(Elements.Address, ElementNamespacePair[Elements.Address]))
                        {
                            // check invalid or empty <Address>
                            var invalidOrEmptyElementForAddress = HandleIncorrectAndEmptyElement<string>(reader, Elements.Address);
                            if (invalidOrEmptyElementForAddress.Exists)
                                continue;

                            // <Address>
                            reader.ReadStartElement();  
                            reader.MoveToContent();

                            tokenEndpoint = Trim(reader.ReadContentAsString());

                            // </Address>
                            reader.MoveToContent();
                            reader.ReadEndElement();
                        }
                        else
                        {
                            reader.ReadOuterXml();
                        }
                    }

                    // </EndpointReference>
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }
                else
                {
                    reader.ReadOuterXml();
                }
            }

            // </PassiveRequestorEndpoint>
            reader.MoveToContent();
            reader.ReadEndElement();

            if (string.IsNullOrEmpty(tokenEndpoint))
                Logger.WriteWarning(LogMessages.IDX22803);

            return tokenEndpoint;
        }

        private static bool IsSecurityTokenServiceTypeRoleDescriptor(XmlReader reader)
        {
            if (reader == null || !reader.IsStartElement(Elements.RoleDescriptor, ElementNamespacePair[Elements.RoleDescriptor]))
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

        internal static ElementResult<T> HandleIncorrectAndEmptyElement<T>(XmlReader reader, string element)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            var result = new ElementResult<T>();

            if (!ElementNamespacePair.ContainsKey(element))
                throw new WsFederationException($"{element} is not registered in {nameof(ElementNamespacePair)}.");

            // check invalid element
            if (!reader.IsStartElement(element, ElementNamespacePair[element]))
            {
                Logger.WriteWarning($"Element '{element}' and namespace '{ElementNamespacePair[element]}' are expected, current element and namespace are '{reader.Name}', '{reader.NamespaceURI}'");
                return result;
            }

            // additional check for KeyDescriptor and RoleDescriptor
            if (element.Equals(Elements.RoleDescriptor) && !IsSecurityTokenServiceTypeRoleDescriptor(reader))
            {
                Logger.WriteWarning("SecurityTokenService type RoleDescriptor is expected.");
                return result;
            }
            else if (element.Equals(Elements.KeyDescriptor) && !keyUse.Signing.Equals(reader.GetAttribute(Attributes.Use)))
            {
                Logger.WriteWarning("KeyDescriptor with signing key use is expected.");
                return result;
            }

            // check empty element
            if (reader.IsEmptyElement)
            {
                Logger.WriteWarning($"Current element '{element}' is an empty element.");
                if (Elements.EntityDescriptor.Equals(element))
                {
                    var issuer = reader.GetAttribute(Attributes.EntityId);
                    if (string.IsNullOrEmpty(issuer))
                        Logger.WriteWarning(LogMessages.IDX22801);
                    (result.ResultObject as WsFederationConfiguration).Issuer = issuer;
                }
                reader.ReadStartElement();
                reader.MoveToContent();
                return result;
            }

            result.Exists = false;
            return result;
        }

        internal class ElementResult<T>
        {
            public bool Exists;
            public T ResultObject;
            public ElementResult()
            {
                Exists = false;
                if (typeof(string) == typeof(T))
                    ResultObject = default(T);
                else
                    ResultObject = (T)Activator.CreateInstance(typeof(T));
            }
        }

#endregion

#region Write Metadata

        /// <summary>
        /// Write the content in configuration into writer.
        /// </summary>
        /// <param name="writer">The <see cref="XmlWriter"/> used to write the configuration content.</param>
        /// <param name="configuration">The <see cref="WsFederationConfiguration"/> provided.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="writer"/> or <paramref name="configuration"/> parameter is missing.</exception>
        /// <exception cref="XmlWriteException">if error occurs when writing metadata.</exception>
        public void WriteMetadata(XmlWriter writer, WsFederationConfiguration configuration)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            if (configuration == null)
                throw LogArgumentNullException(nameof(configuration));

            if (configuration.SigningCredentials != null)
                writer = new EnvelopedSignatureWriter(writer, configuration.SigningCredentials, "id");

            if (string.IsNullOrEmpty(configuration.Issuer))
                throw XmlUtil.LogWriteException(LogMessages.IDX22810);

            if (string.IsNullOrEmpty(configuration.TokenEndpoint))
                throw XmlUtil.LogWriteException(LogMessages.IDX22811);

            writer.WriteStartDocument();

            // <EntityDescriptor>
            writer.WriteStartElement(Elements.EntityDescriptor, Namespaces.MetadataNamespace);

            // @entityID
            writer.WriteAttributeString(Attributes.EntityId, configuration.Issuer);

            // <RoleDescriptor>
            writer.WriteStartElement(Elements.RoleDescriptor);
            writer.WriteAttributeString(Xmlns, Prefixes.Xsi, null, XmlSignatureConstants.XmlSchemaNamespace);
            writer.WriteAttributeString(Xmlns, Prefixes.Fed, null, Namespaces.FederationNamespace);
            writer.WriteAttributeString(Prefixes.Xsi, Attributes.Type, null, Prefixes.Fed + ":" + Types.SecurityTokenServiceType);

            // write the key infos
            if (configuration.KeyInfos != null)
            {
                foreach (var keyInfo in configuration.KeyInfos)
                {
                    // <KeyDescriptor>
                    writer.WriteStartElement(Elements.KeyDescriptor);
                    writer.WriteAttributeString(Attributes.Use, keyUse.Signing);
                    _dsigSerializer.WriteKeyInfo(writer, keyInfo);
                    // </KeyDescriptor>
                    writer.WriteEndElement();
                }
            }

            // <fed:PassiveRequestorEndpoint>
            writer.WriteStartElement(Elements.PassiveRequestorEndpoint, Namespaces.FederationNamespace);

            // <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
            writer.WriteStartElement(Prefixes.Wsa, Elements.EndpointReference, Namespaces.AddressingNamespace);

            // <wsa:Address>
            writer.WriteStartElement(Elements.Address, Namespaces.AddressingNamespace);

            // write TokenEndpoint
            writer.WriteString(configuration.TokenEndpoint);

            // </wsa:Address>
            writer.WriteEndElement();

            // </wsa:EndpointReference>
            writer.WriteEndElement();

            // </fed:PassiveRequestorEndpoint>
            writer.WriteEndElement();

            // </RoleDescriptor>
            writer.WriteEndElement();

            // </EntityDescriptor>
            writer.WriteEndElement();

            writer.WriteEndDocument();
        }

#endregion
    }
}
