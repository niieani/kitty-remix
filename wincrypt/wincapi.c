/*
 * PuTTY wincrypt patch main file.
 * Author: Ulf Frisk, puttywincrypt@ulffrisk.com
 */
#include <windows.h>
#include <wincrypt.h>
#include "ssh.h"

/*
 * Defines and declarations due to mssing declarations in mingw32 headers.
 * CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_PROV_MEMORY,
 * CRYPT_FIND_USER_KEYSET_FLAG, CRYPT_FIND_SILENT_KEYSET_FLAG,
 * CERT_CLOSE_STORE_FORCE_FLAG, CryptFindCertificateKeyProvInfo,
 * CryptUIDlgSelectCertificateFromStore
 */
#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_CURRENT_USER (1 << 16)
#endif /* CERT_SYSTEM_STORE_CURRENT_USER */

#ifndef CERT_STORE_PROV_MEMORY
#define CERT_STORE_PROV_MEMORY ((LPCSTR) 2)
#endif /* CERT_STORE_PROV_MEMORY */

#ifndef CRYPT_FIND_USER_KEYSET_FLAG
#define CRYPT_FIND_USER_KEYSET_FLAG 0x00000001
#endif /* CRYPT_FIND_USER_KEYSET_FLAG */

#ifndef CRYPT_FIND_SILENT_KEYSET_FLAG
#define CRYPT_FIND_SILENT_KEYSET_FLAG 0x00000040
#endif /* CRYPT_FIND_SILENT_KEYSET_FLAG */

#ifndef CERT_CLOSE_STORE_FORCE_FLAG
#define CERT_CLOSE_STORE_FORCE_FLAG 0x00000001
#endif /* CERT_CLOSE_STORE_FORCE_FLAG */

#ifndef CRYPT_ACQUIRE_NO_HEALING
#define CRYPT_ACQUIRE_NO_HEALING 0x00000008
#endif /* CRYPT_ACQUIRE_NO_HEALING */

/*
 * Defines and declarations due to mssing declarations in BCC55 headers.
 * CRYPT_ACQUIRE_SILENT_FLAG
 */
#ifndef CRYPT_ACQUIRE_SILENT_FLAG
#define CRYPT_ACQUIRE_SILENT_FLAG 0x00000040
#endif /* CRYPT_ACQUIRE_SILENT_FLAG */

typedef PCCERT_CONTEXT (WINAPI *DFNCryptUIDlgSelectCertificateFromStore)(HCERTSTORE, HWND, LPCWSTR, LPCWSTR, DWORD, DWORD, void*);

/*
 * convert sha1 string to binary data
 */
void capi_sha1_to_binary(PSTR szHex, PBYTE pbBin)
{
	unsigned char i, h, l;
	for(i = 0; i < 20; i++) {
		h = szHex[i<<1];
		l = szHex[(i<<1) + 1];
		pbBin[i] = 
			(((h >= '0' && h <= '9') ? h - '0' : ((h >= 'a' && h <= 'f') ? h - 'a' + 10 : ((h >= 'A' && h <= 'F') ? h - 'A' + 10 : 0))) << 4) + 
			(((l >= '0' && l <= '9') ? l - '0' : ((l >= 'a' && l <= 'f') ? l - 'a' + 10 : ((l >= 'A' && l <= 'F') ? l - 'A' + 10 : 0))));
	}
}

/*
 * windows XP do not support CryptBinaryToString with raw hex
 */
PSTR capi_binary_to_hex(PBYTE pbBinary, DWORD cbBinary)
{
	PSTR szHex;
	DWORD idx;
	BYTE b;
	szHex = snewn((cbBinary << 1) + 1, char);
	szHex[cbBinary << 1] = 0;
	for(idx = 0; idx < cbBinary; idx++) {
		b = (pbBinary[idx] >> 4) & 0x0F;
		szHex[idx << 1] = (b < 10)?b+'0':b-10+'a';
		b = pbBinary[idx] & 0x0F;
		szHex[(idx << 1) + 1] = (b < 10)?b+'0':b-10+'a';
	}
	return szHex;
}

/*
 * Reverse a byte array.
 */
void capi_reverse_array(PBYTE pb, DWORD cb)
{
	DWORD i;
	BYTE t;
	for(i = 0; i < cb >> 1; i++) {
		t = pb[i];
		pb[i] = pb[cb-i-1];
		pb[cb-i-1] = t;
	}
}

/*
 * select a certificate given the criterias provided
 * if a criteria is absent it will be disregarded
 */
void capi_select_cert_2(PBYTE pbSHA1, LPWSTR wszCN, PCCERT_CONTEXT *ppCertCtx, HCERTSTORE *phStore)
{
	HCERTSTORE hStoreMY = NULL, hStoreTMP = NULL;
	PCCERT_CONTEXT pCertCtx = NULL;
	HMODULE hCryptUIDLL = NULL;
	DFNCryptUIDlgSelectCertificateFromStore dfnCryptUIDlgSelectCertificateFromStore;
	CRYPT_HASH_BLOB cryptHashBlob;
	HCRYPTPROV hCryptProv;
	DWORD dwCertCount = 0, dwKeySpec;
	BOOL fCallerFreeProv;
	if(!(hStoreMY = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY"))) {
		goto error;
	}
	if(pbSHA1) {
		cryptHashBlob.cbData = 20;
		cryptHashBlob.pbData = pbSHA1;
		if((*ppCertCtx = CertFindCertificateInStore(hStoreMY, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &cryptHashBlob, pCertCtx))) {
			*phStore = hStoreMY;
			return;
		} else {
			goto error;
		}
	}
	if(!(hStoreTMP = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL))) {
		goto error;
	}
	while(TRUE) {
		if(wszCN) {
			pCertCtx = CertFindCertificateInStore(hStoreMY, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, wszCN, pCertCtx);
		} else {
			pCertCtx = CertEnumCertificatesInStore(hStoreMY, pCertCtx);
		}
		if(!pCertCtx) {
			break;
		}
		if(!CryptAcquireCertificatePrivateKey(pCertCtx, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_NO_HEALING | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &hCryptProv, &dwKeySpec, &fCallerFreeProv)) {
			continue;
		}
		if(fCallerFreeProv) {
			CryptReleaseContext(hCryptProv, 0);
		}
		dwCertCount++;
		CertAddCertificateContextToStore(hStoreTMP, pCertCtx, CERT_STORE_ADD_ALWAYS, NULL);
	}
	CertCloseStore(hStoreMY, CERT_CLOSE_STORE_FORCE_FLAG);
	hStoreMY = NULL;
	if(dwCertCount == 1) {
		*ppCertCtx = CertEnumCertificatesInStore(hStoreTMP, NULL);
		*phStore = hStoreTMP;
		return;
	} else if((dwCertCount > 1) &&
		(hCryptUIDLL = LoadLibrary("cryptui.dll")) &&
		(dfnCryptUIDlgSelectCertificateFromStore = (DFNCryptUIDlgSelectCertificateFromStore)GetProcAddress(hCryptUIDLL, "CryptUIDlgSelectCertificateFromStore")) &&
		(*ppCertCtx = dfnCryptUIDlgSelectCertificateFromStore(hStoreTMP, NULL, NULL, NULL, 0, 0, NULL))) {
		*phStore = hStoreTMP;
		FreeLibrary(hCryptUIDLL);
		return;
	}
error:
	if(hCryptUIDLL) { FreeLibrary(hCryptUIDLL); }
	if(hStoreTMP)	{ CertCloseStore(hStoreTMP, CERT_CLOSE_STORE_FORCE_FLAG); }
	if(hStoreMY)	{ CertCloseStore(hStoreMY, CERT_CLOSE_STORE_FORCE_FLAG); }
	*ppCertCtx = NULL;
	*phStore = NULL;
}

/*
 * return a malloc'ed string containing the requested subitem
 */
PSTR capi_select_cert_finditem(PSTR szCert, PCSTR szStart)
{
	PSTR ptrStart, ptrEnd, szResult;
	ptrStart = strstr(szCert, szStart);
	ptrEnd = strstr(szCert, ",");
	if(!ptrEnd || ptrEnd < ptrStart) {
		ptrEnd = szCert + strlen(szCert);
	}
	if(!ptrStart || ptrStart > ptrEnd) {
		return NULL;
	}
	ptrStart += strlen(szStart);
	szResult = (PSTR)calloc(ptrEnd - ptrStart + 1, sizeof(char));
	memcpy(szResult, ptrStart, ptrEnd - ptrStart);
	return szResult;
}

/*
 * select a certificate given the definition string
 */
void capi_select_cert(PSTR szCert, PCCERT_CONTEXT *ppCertCtx, HCERTSTORE *phStore)
{
	PSTR szCN = NULL, szThumb, ptrStart, ptrStartAll;
	LPWSTR wszCN = NULL;
	DWORD i, len;
	PBYTE pbThumb = snewn(20, BYTE);
	ptrStart = strstr(szCert, "cert://");
	ptrStartAll = strstr(szCert, "cert://*");
	if(ptrStart != szCert) {
		*ppCertCtx = NULL;
		*phStore = NULL;
		return;
	}
	if(ptrStartAll) {
		capi_select_cert_2(NULL, NULL, ppCertCtx, phStore);
		return;
	}
	szThumb = capi_select_cert_finditem(szCert, "thumbprint=");
	if(szThumb && 40 == strlen(szThumb)) {
		capi_sha1_to_binary(szThumb, pbThumb);
		capi_select_cert_2(pbThumb, NULL, ppCertCtx, phStore);
	} else {
		szCN = capi_select_cert_finditem(szCert, "cn=");
		if(szCN) {
			len = strlen(szCN);
			wszCN = (LPWSTR)calloc(len + 1, sizeof(wchar_t));
			for(i = 0; i < len; i++) {
				wszCN[i] = szCN[i];
			}
		}
		capi_select_cert_2(NULL, wszCN, ppCertCtx, phStore);
	}
	if(szCN) { free(szCN); }
	if(wszCN) { free(wszCN); }
	sfree(pbThumb);
}

/* 
 * get rsa key comment on the form "cert://cn=<cn>,thumbprint=<sha1>"
 */
static PSTR capi_get_description(PCCERT_CONTEXT pCertContext)
{
	unsigned int cbCN;
	PSTR szCN, szSHA1, szResult;
	unsigned char hash[20];
	cbCN = CertGetNameStringA(pCertContext, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, szCN = snewn(FILENAME_MAX, char), FILENAME_MAX);
	SHA_Simple(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, hash);
	szSHA1 = capi_binary_to_hex(hash, 20);
	szResult = ((cbCN > 0) && (cbCN < FILENAME_MAX - 64)) ? 
		dupcat("cert://cn=", szCN, ",thumbprint=", szSHA1, NULL) : 
		dupcat("cert://thumbprint=", szSHA1, NULL);
	sfree(szCN);
	sfree(szSHA1);
	return szResult;
}

/*
 * load a rsa key from a certificate in windows certificate personal store
 */
void *capi_load_key(unsigned char **blob, int *len) 
{
	BOOL result;
	PCCERT_CONTEXT pCertContext;
	HCERTSTORE hCertStore;
	DWORD cbPublicKeyBlob = 8192;
	PBYTE pbPublicKeyBlob = NULL;
	RSAPUBKEY *pRSAPubKey;
    struct RSAKey *rsa;
	/* instantiate certificate and retrieve public key blob */
	if((*len < 7) || 0 != strncmp("cert://", (PSTR)*blob, 7)) {
		return NULL;
	}
	capi_select_cert((PSTR)*blob, &pCertContext, &hCertStore);
	if(!pCertContext) {
		return NULL;
	}
	result = CryptDecodeObject(
		X509_ASN_ENCODING, 
		RSA_CSP_PUBLICKEYBLOB, 
		pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, 
		pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, 
		0, 
		(void*)(pbPublicKeyBlob = snewn(cbPublicKeyBlob, BYTE)),
		&cbPublicKeyBlob);
	if(!result) {
		CertFreeCertificateContext(pCertContext);
		sfree(pbPublicKeyBlob);
		return NULL;
	}
	pRSAPubKey = (RSAPUBKEY*)(pbPublicKeyBlob + sizeof(BLOBHEADER));
	/* create rsa key, set properties [no need for private_exponent,p,q,iqmp] */
	rsa = snew(struct RSAKey);
	rsa->bits = pRSAPubKey->bitlen;
	rsa->bytes = pRSAPubKey->bitlen / 8;
	rsa->exponent = bignum_from_long(pRSAPubKey->pubexp);
	capi_reverse_array(pbPublicKeyBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY), pRSAPubKey->bitlen / 8);
	rsa->modulus = bignum_from_bytes((unsigned char*)pbPublicKeyBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY), pRSAPubKey->bitlen / 8);
	rsa->comment = capi_get_description(pCertContext);
    rsa->private_exponent = bignum_from_long(0);
    rsa->p = bignum_from_long(0);
    rsa->q = bignum_from_long(0);
    rsa->iqmp = bignum_from_long(0);
	/* cleanup */
	sfree(pbPublicKeyBlob);
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
    return rsa;
}

/*
 * check whether the supplied key is a capi key or not
 */
BOOL capi_is_capikey(struct RSAKey *rsa)
{
	return
		0 == bignum_bitcount(rsa->p) &&
		0 == bignum_bitcount(rsa->q) &&
		0 == bignum_bitcount(rsa->iqmp) &&
		0 == bignum_bitcount(rsa->private_exponent) &&
		NULL != rsa->comment &&
		NULL != strstr(rsa->comment, "cert://");
}

/*
 * perform the signing operation
 */
Bignum capi_rsa2_sign(struct RSAKey *rsa, char *data, int datalen)
{
	Bignum ret = NULL;
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertCtx;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	PBYTE pbSig = NULL;
	DWORD dwSpec, cbSig = 0;
	BOOL fDmy;
	/* perform the signing operation (terminate on any error) */
	capi_select_cert(rsa->comment, &pCertCtx, &hCertStore);
	if( pCertCtx &&
		CryptAcquireCertificatePrivateKey(pCertCtx, 0, 0, &hProv, &dwSpec, &fDmy) &&
		CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash) &&
		CryptHashData(hHash, (PBYTE)data, datalen, 0) &&
		CryptSignHash(hHash, dwSpec, NULL, 0, NULL, &cbSig) &&
		CryptSignHash(hHash, dwSpec, NULL, 0, pbSig = snewn(cbSig, BYTE), &cbSig)) {
		capi_reverse_array(pbSig, cbSig);
		ret = bignum_from_bytes(pbSig, cbSig);
	}
	if(pbSig) { sfree(pbSig); }
	if(hHash) { CryptDestroyHash(hHash); }
	if(hProv) { CryptReleaseContext(hProv, 0); } 
	if(pCertCtx) { CertFreeCertificateContext(pCertCtx); }
	if(hCertStore) { CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG); }
	return ret?ret:bignum_from_long(0);
}