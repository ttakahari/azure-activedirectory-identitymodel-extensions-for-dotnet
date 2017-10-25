using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Tokens
{
    internal class MethodInAssembly
    {
        public delegate AsymmetricAlgorithm GetKeyDelegateAsymmetricAlgorithm(X509Certificate2 certificate);

        public delegate RSA GetKeyDelegateRSA(X509Certificate2 certificate);

        private static GetKeyDelegateAsymmetricAlgorithm _getPrivateKeyDelegateAsymmetricAlgorithm = null;

        private static GetKeyDelegateAsymmetricAlgorithm _getPublicKeyDelegateAsymmetricAlgorithm = null;

        private static GetKeyDelegateRSA _getPrivateKeyDelegateRSA = null;

        private static GetKeyDelegateRSA _getPublicKeyDelegateRSA = null;

        private static bool _delegateSet = false;

#if NETSTANDARD1_4
        private static HashAlgorithmName GetHashAlgorithmname(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Sha256:
                    return HashAlgorithmName.SHA256;
                case SecurityAlgorithms.Sha384:
                    return HashAlgorithmName.SHA384;
                case SecurityAlgorithms.Sha512:
                    return HashAlgorithmName.SHA512;
            }
            throw new Exception("some");
        }
#endif

        public static byte[] SignData(RSA rsa, byte[] data, string algorithm)
        {
#if (NET45 || NET451)
            Assembly mscorlibAssembly = null;
            foreach (var assem in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (assem.GetName().Name == "mscorlib")
                {
                    mscorlibAssembly = assem;
                }
            }

            if (mscorlibAssembly != null)
            {
                Type hashAlgorithmNameType = mscorlibAssembly.GetType("System.Security.Cryptography.HashAlgorithmName");
                Type paddingType = mscorlibAssembly.GetType("System.Security.Cryptography.RSASignaturePadding");
                var _Pkcs1Padding = paddingType.GetProperty("Pkcs1").GetValue(null);
                Type type = mscorlibAssembly.GetType("System.Security.Cryptography.RSA");

                object hashAlgorithm = null;
                switch (algorithm)
                {
                    case SecurityAlgorithms.Sha256:
                        hashAlgorithm = hashAlgorithmNameType.GetProperty("SHA256").GetValue(null);
                        break;

                    case SecurityAlgorithms.Sha384:
                        hashAlgorithm = hashAlgorithmNameType.GetProperty("SHA384").GetValue(null);
                        break;

                    case SecurityAlgorithms.Sha512:
                        hashAlgorithm = hashAlgorithmNameType.GetProperty("SHA512").GetValue(null);
                        break;
                }

                var method = type.GetMethod("SignData", new Type[] { typeof(Byte[]), hashAlgorithmNameType, paddingType });
                try
                {
                    return method.Invoke(rsa, new object[] { data, hashAlgorithm, _Pkcs1Padding }) as Byte[];
                }
                catch(Exception ex)
                {
                    throw ex.InnerException;
                }
            }

            return null;
#else
            return rsa.SignData(data, GetHashAlgorithmname(algorithm), RSASignaturePadding.Pkcs1);
#endif
        }

        public static byte[] SignData(ECDsa ecdsa, byte[] data, string algorithm = null)
        {

#if NETSTANDARD1_4
            return ecdsa.SignData(data, GetHashAlgorithmname(algorithm));
#else
            return (ecdsa as ECDsaCng).SignData(data);
#endif
        }

        public static bool VerifyData(RSA rsa, byte[] data, byte[] signature, string algorithm)
        {
#if (NET45 || NET451)
            Assembly mscorlibAssembly = null;
            foreach (var assem in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (assem.GetName().Name == "mscorlib")
                {
                    mscorlibAssembly = assem;
                }
            }

            if (mscorlibAssembly != null)
            {
                Type hashAlgorithmNameType = mscorlibAssembly.GetType("System.Security.Cryptography.HashAlgorithmName");
                Type paddingType = mscorlibAssembly.GetType("System.Security.Cryptography.RSASignaturePadding");
                var _Pkcs1Padding = paddingType.GetProperty("Pkcs1").GetValue(null);
                Type type = mscorlibAssembly.GetType("System.Security.Cryptography.RSA");

                object hashAlgorithm = null;
                switch (algorithm)
                {
                    case SecurityAlgorithms.Sha256:
                        hashAlgorithm = hashAlgorithmNameType.GetProperty("SHA256").GetValue(null);
                        break;

                    case SecurityAlgorithms.Sha384:
                        hashAlgorithm = hashAlgorithmNameType.GetProperty("SHA384").GetValue(null);
                        break;

                    case SecurityAlgorithms.Sha512:
                        hashAlgorithm = hashAlgorithmNameType.GetProperty("SHA512").GetValue(null);
                        break;
                }

                var method = type.GetMethod("VerifyData", new Type[] { typeof(Byte[]), typeof(Byte[]), hashAlgorithmNameType, paddingType });
                return (bool)method.Invoke(rsa, new object[] { data, signature, hashAlgorithm, _Pkcs1Padding });
            }

            return false;
#else
            return rsa.VerifyData(data, signature, GetHashAlgorithmname(algorithm), RSASignaturePadding.Pkcs1);
#endif
        }

        public static bool VerifyData(ECDsa ecdsa, byte[] data, byte[] signature, string algorithm = null)
        {
#if NETSTANDARD1_4
            return ecdsa.VerifyData(data, signature, GetHashAlgorithmname(algorithm));
#else
            return (ecdsa as ECDsaCng).VerifyData(data, signature);
#endif
        }

        public static byte[] Decrypt(RSA rsa, byte[] data, bool fOAEP)
        {
#if (NET45 || NET451)
            Assembly mscorlibAssembly = null;
            foreach (var assem in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (assem.GetName().Name == "mscorlib")
                {
                    mscorlibAssembly = assem;
                }
            }

            if (mscorlibAssembly != null)
            {
                Type paddingType = mscorlibAssembly.GetType("System.Security.Cryptography.RSAEncryptionPadding");
                var sha1Padding = paddingType.GetProperty("OaepSHA1").GetValue(null);
                var pkcs1Padding = paddingType.GetProperty("Pkcs1").GetValue(null);
                Type type = mscorlibAssembly.GetType("System.Security.Cryptography.RSA");

                var method = type.GetMethod("Decrypt");
                if (fOAEP)
                    return method.Invoke(rsa, new object[] { data, sha1Padding }) as Byte[];
                else
                    return method.Invoke(rsa, new object[] { data, pkcs1Padding }) as Byte[];
            }

            return null;
#else
            if (fOAEP)
                return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA1);
            else
                return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
#endif
        }

        public static byte[] Encrypt(RSA rsa, byte[] data, bool fOAEP)
        {
#if (NET45 || NET451)
            Assembly mscorlibAssembly = null;
            foreach (var assem in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (assem.GetName().Name == "mscorlib")
                {
                    mscorlibAssembly = assem;
                }
            }

            if (mscorlibAssembly != null)
            {
                Type paddingType = mscorlibAssembly.GetType("System.Security.Cryptography.RSAEncryptionPadding");
                var sha1Padding = paddingType.GetProperty("OaepSHA1").GetValue(null);
                var pkcs1Padding = paddingType.GetProperty("Pkcs1").GetValue(null);
                Type type = mscorlibAssembly.GetType("System.Security.Cryptography.RSA");

                var method = type.GetMethod("Encrypt");
                if (fOAEP)
                    return method.Invoke(rsa, new object[] { data, sha1Padding }) as Byte[];
                else
                    return method.Invoke(rsa, new object[] { data, pkcs1Padding }) as Byte[];
            }

            return null;
#else
            if (fOAEP)
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA1);
            else
                return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
#endif
        }

        private static void SetDelegate()
        {
            if (_delegateSet)
                return;

            _delegateSet = true;

#if (NET45 || NET451 || NET452 || NET46)
            Assembly systemCoreAssembly = null;
            foreach (var assem in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (assem.GetName().Name == "System.Core")
                {
                    systemCoreAssembly = assem;
                }
            }

            if (systemCoreAssembly != null)
            {
                Type type = systemCoreAssembly.GetType("System.Security.Cryptography.X509Certificates.RSACertificateExtensions");
                if (type != null)
                {
                    var getPrivateKeyMethod = type.GetMethod("GetRSAPrivateKey");
                    if (getPrivateKeyMethod != null)
                    {
                        _getPrivateKeyDelegateRSA = certificate =>
                        {
                            object[] staticParameters = { certificate };
                            return getPrivateKeyMethod.Invoke(null, staticParameters) as RSA;
                        };
                    }

                    var getPublicKeyMethod = type.GetMethod("GetRSAPublicKey");
                    if (getPublicKeyMethod != null)
                    {
                        _getPublicKeyDelegateRSA = certificate =>
                        {
                            object[] staticParameters = { certificate };
                            return getPublicKeyMethod.Invoke(null, staticParameters) as RSA;
                        };
                    }
                }
            }

            if (_getPrivateKeyDelegateAsymmetricAlgorithm == null)
            {
                _getPrivateKeyDelegateAsymmetricAlgorithm = certificate =>
                {
                    return certificate.PrivateKey;
                };
            }

            if (_getPublicKeyDelegateAsymmetricAlgorithm == null)
            {
                _getPublicKeyDelegateAsymmetricAlgorithm = certificate =>
                {
                    return certificate.PublicKey.Key;
                };
            }
#else
            _getPrivateKeyDelegateRSA = certificate =>
            {
                return RSACertificateExtensions.GetRSAPrivateKey(certificate);
            };

            _getPublicKeyDelegateRSA = certificate =>
            {
                return RSACertificateExtensions.GetRSAPublicKey(certificate);
            };
#endif
        }

        public static void SetPrivateKey(X509Certificate2 certificate, RsaAlgorithm rsaAlgorithm)
        {
            SetDelegate();
#if NETSTANDARD1_4
            rsaAlgorithm.rsa = _getPrivateKeyDelegateRSA(certificate);
#else
            if (_getPrivateKeyDelegateRSA != null)
                rsaAlgorithm.rsa = _getPrivateKeyDelegateRSA(certificate);
            else
                rsaAlgorithm.rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(_getPrivateKeyDelegateAsymmetricAlgorithm(certificate) as RSACryptoServiceProvider);
#endif
        }

        public static void SetPublicKey(X509Certificate2 certificate, RsaAlgorithm rsaAlgorithm)
        {
            SetDelegate();
#if NETSTANDARD1_4
            rsaAlgorithm.rsa = _getPublicKeyDelegateRSA(certificate);
#else
            if (_getPublicKeyDelegateRSA != null)
                rsaAlgorithm.rsa = _getPublicKeyDelegateRSA(certificate);
            else
                rsaAlgorithm.rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(_getPublicKeyDelegateAsymmetricAlgorithm(certificate) as RSACryptoServiceProvider);
#endif
        }

        public static AsymmetricAlgorithm GetPrivateKey(X509Certificate2 certificate)
        {
            SetDelegate();
            if (_getPrivateKeyDelegateRSA != null)
                return _getPrivateKeyDelegateRSA(certificate) as AsymmetricAlgorithm;
            else
                return _getPrivateKeyDelegateAsymmetricAlgorithm(certificate);
        }

        public static AsymmetricAlgorithm GetPublicKey(X509Certificate2 certificate)
        {
            SetDelegate();
            if (_getPublicKeyDelegateRSA != null)
                return _getPublicKeyDelegateRSA(certificate) as AsymmetricAlgorithm;
            else
                return _getPublicKeyDelegateAsymmetricAlgorithm(certificate);
        }
    }
}
