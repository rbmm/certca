#include "certca.h"
//#include <CertSrv.h >
//#include "certca priv.h"

#pragma comment(lib, "certca.lib")

void DumpExtensions(HCERTTYPE hCertType);

HRESULT Clone(_In_ PCWSTR wszCertType, _In_ PCWSTR wszFriendlyName)
{
	HRESULT hr; 
	HCERTTYPE hCertType, hNewCertType;

	if (0 <= (hr = CAFindCertTypeByName(wszCERTTYPE_USER_SMARTCARD_LOGON, 0, CT_ENUM_USER_TYPES|CT_FLAG_NO_CACHE_LOOKUP, &hCertType)))
	{
		hr = CACloneCertType(hCertType, wszCertType, wszFriendlyName, 0, 
			CT_CLONE_KEEP_AUTOENROLLMENT_SETTING|CT_CLONE_KEEP_SUBJECT_NAME_SETTING, &hNewCertType);

		CACloseCertType(hCertType);

		if (0 <= hr)
		{
			DumpExtensions(hNewCertType);

			static PCWSTR EKU[] = { 
				_CRT_WIDE(szOID_KP_SMARTCARD_LOGON), 
				_CRT_WIDE(szOID_PKIX_KP_CLIENT_AUTH),
				NULL
			};

			0 <= (hr = CADCSetCertTypePropertyEx(hNewCertType, CERTTYPE_PROP_EXTENDED_KEY_USAGE, EKU, 0)) &&
				0 <= (hr = CASetCertTypeFlagsEx(hNewCertType, CERTTYPE_SUBJECT_NAME_FLAG, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)) &&
				0 <= (hr = CASetCertTypeFlagsEx(hNewCertType, CERTTYPE_PRIVATE_KEY_FLAG, CT_FLAG_EXPORTABLE_KEY)) &&
				0 <= (hr = CAUpdateCertType(hNewCertType));

			CACloseCertType(hNewCertType);
		}
	}

	return hr;
}

void DumpExtensions(HCERTTYPE hCertType)
{
	PCERT_EXTENSIONS pCertExtensions;

	if (0 <= CAGetCertTypeExtensions(hCertType, &pCertExtensions))
	{
		if (DWORD cExtension = pCertExtensions->cExtension)
		{
			PCERT_EXTENSION rgExtension = pCertExtensions->rgExtension;
			do 
			{
				PCSTR pszObjId = rgExtension->pszObjId;

				DbgPrint("[%x] %s\n", rgExtension->fCritical, pszObjId);

				union {
					PVOID pv;
					PCERT_TEMPLATE_EXT pte;
					PCERT_POLICIES_INFO ppqi;
					PCERT_ENHKEY_USAGE peu;
					PCRYPT_BIT_BLOB pbb;
				};

				if (!strcmp(pszObjId, szOID_APPLICATION_CERT_POLICIES))
				{
					pszObjId = szOID_CERT_POLICIES;
				}

				ULONG cb;
				if (CryptDecodeObjectEx(X509_ASN_ENCODING, pszObjId, 
					rgExtension->Value.pbData, rgExtension->Value.cbData,
					CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 
					0, &pv, &cb))
				{
					if (!strcmp(pszObjId, szOID_CERTIFICATE_TEMPLATE))
					{
						DbgPrint("\t%x.%x %s\n", pte->dwMajorVersion, pte->dwMinorVersion, pte->pszObjId);
					}
					else if (!strcmp(pszObjId, szOID_ENHANCED_KEY_USAGE))
					{
						if (DWORD cUsageIdentifier = peu->cUsageIdentifier)
						{
							PSTR *rgpszUsageIdentifier = peu->rgpszUsageIdentifier;
							do 
							{
								DbgPrint("\t%s\n", *rgpszUsageIdentifier++);

							} while (--cUsageIdentifier);
						}
					}
					else if (!strcmp(pszObjId, szOID_KEY_USAGE))
					{
						char sz[16];
						ULONG cch = _countof(sz);
						if (CryptBinaryToStringA(pbb->pbData, pbb->cbData,
							CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF, sz, &cch))
						{
							DbgPrint("\t%s\n", sz);
						}
					}
					else if (!strcmp(pszObjId, szOID_CERT_POLICIES))
					{
						if (DWORD cPolicyInfo = ppqi->cPolicyInfo)
						{
							CERT_POLICY_INFO *rgPolicyInfo = ppqi->rgPolicyInfo;
							do 
							{
								DbgPrint("\t%s\n", rgPolicyInfo->pszPolicyIdentifier);
							} while (rgPolicyInfo++, --cPolicyInfo);
						}
					}

					LocalFree(pv);
				}
			} while (rgExtension++, --cExtension);
		}

		CAFreeCertTypeExtensions(hCertType, pCertExtensions);
	}
}