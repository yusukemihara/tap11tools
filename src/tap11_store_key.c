/* p11tools, simple utility software to operate security token device
 * Copyright (C) 2014 yusuke mihara <mihara@netlab.jp>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libp11.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int
tap11_store_key(
	const char *libp11,
	const char *pin,
	const char *keyid,
	const char *keyfile)
{
	int rc;
	unsigned int nslots;
	PKCS11_CTX *p11ctx;
	PKCS11_SLOT *slots, *slot;
	RSA *rsa;
	EVP_PKEY *pk;
	BIO *bio;

	p11ctx = PKCS11_CTX_new();

	/* load pkcs #11 module */
	rc = PKCS11_CTX_load(p11ctx,libp11);
	if (rc) {
		fprintf(stderr,"PKCS11_CTX_load\n");
		return -1;
	}

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(p11ctx, &slots, &nslots);
	if (rc < 0) {
		fprintf(stderr,"PKCS11_enumerate_slots\n");
		return -1;
	}

	/* get first slot with a token */
	slot = PKCS11_find_token(p11ctx, slots, nslots);
	if (!slot || !slot->token) {
		fprintf(stderr,"PKCS11_find_token\n");
		return -1;
	}

	fprintf(stderr,"Slot manufacturer......: %s\n", slot->manufacturer);
	fprintf(stderr,"Slot description.......: %s\n", slot->description);
	fprintf(stderr,"Slot token label.......: %s\n", slot->token->label);
	fprintf(stderr,"Slot token manufacturer: %s\n", slot->token->manufacturer);
	fprintf(stderr,"Slot token model.......: %s\n", slot->token->model);
	fprintf(stderr,"Slot token serialnr....: %s\n", slot->token->serialnr);

	rc = PKCS11_open_session(slot, 1);
	if (rc != 0) {
		ERR_load_PKCS11_strings();
		fprintf(stderr,"PKCS11_open_session %s\n",
			ERR_reason_error_string(ERR_get_error()));
		return -1;
	}

	rc = PKCS11_login(slot, 0, pin);
	if (rc != 0) {
		ERR_load_PKCS11_strings();
		fprintf(stderr,"PKCS11_login %s\n",
			ERR_reason_error_string(ERR_get_error()));
		return -1;
	}

	/* load key */
	if ((bio = BIO_new(BIO_s_file())) == NULL)
	{
		fprintf(stderr,"BIO_new\n");
		return -1;
	}
	if (BIO_read_filename(bio,keyfile) <= 0) {
		fprintf(stderr,"BIO_read_filename\n");
		return -1;
	}
	rsa = PEM_read_bio_RSAPrivateKey(bio,NULL,NULL,NULL);
	if (rsa == NULL) {
		fprintf(stderr,"PEM_read_bio_RSAPrivateKey\n");
		return -1;
	}
	BIO_free(bio);

	pk = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pk,rsa);

	/* store key */
	rc = PKCS11_store_private_key(slot->token,pk,
			(char*)keyid,(unsigned char*)keyid,strlen(keyid));
	if (rc != 0) {
		ERR_load_PKCS11_strings();
		fprintf(stderr,"PKCS11_store_private_key %s rc:%d\n",
			ERR_reason_error_string(ERR_get_error()),rc);
		return -1;
	}

	rc = PKCS11_store_public_key(slot->token,pk,
			(char*)keyid,(unsigned char*)keyid,strlen(keyid));
	if (rc != 0) {
		ERR_load_PKCS11_strings();
		fprintf(stderr,"PKCS11_store_public_key %s rc:%d\n",
			ERR_reason_error_string(ERR_get_error()),rc);
		return -1;
	}

	EVP_PKEY_free(pk);

	PKCS11_logout(slot);
	PKCS11_release_all_slots(p11ctx, slots, nslots);
	PKCS11_CTX_unload(p11ctx);
	PKCS11_CTX_free(p11ctx);

	fprintf(stderr,"\n\nstore key succeed\n");

	return 0;
}

int 
main(int argc,char *argv[])
{
	if (argc < 5) {
		fprintf(stderr,"%% tap11_store_key pkcs11.so pin keyid key.pem\n");
		return 1;
	}
	return tap11_store_key(argv[1],argv[2],argv[3],argv[4]);
}
