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
#include <openssl/engine.h>

/* FIXME have to get from configure */
#define ENGINE_PKCS11_PATH "/usr/lib/ssl/engines/engine_pkcs11.so"

static char *
get_engine_keyid(
	const char *p11lib,
	const char *pin,
	const char *keyid)
{
	int i,rc;
	unsigned int nslots,nslot;
	char part[3],*ekeyid,*p;
	PKCS11_CTX *p11ctx;
	PKCS11_SLOT *slots, *slot;
	size_t size;

	nslot = 0;

	p11ctx = PKCS11_CTX_new();

	/* load pkcs #11 module */
	rc = PKCS11_CTX_load(p11ctx,p11lib);
	if (rc) {
		fprintf(stderr,"PKCS11_CTX_load\n");
		exit(-1);
	}

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(p11ctx, &slots, &nslots);
	if (rc < 0) {
		fprintf(stderr,"PKCS11_enumerate_slots\n");
		exit(-1);
	}

	/* get first slot with a token */
	slot = PKCS11_find_token(p11ctx, slots, nslots);
	if (!slot || !slot->token) {
		fprintf(stderr,"PKCS11_find_token\n");
		exit(-1);
	}
	for(i=0;i<nslots;i++) {
		if (&slots[i] == slot) {
			nslot = i + 1;
		}
	}

	fprintf(stderr,"Slot manufacturer......: %s\n", slot->manufacturer);
	fprintf(stderr,"Slot description.......: %s\n", slot->description);
	fprintf(stderr,"Slot token label.......: %s\n", slot->token->label);
	fprintf(stderr,"Slot token manufacturer: %s\n", slot->token->manufacturer);
	fprintf(stderr,"Slot token model.......: %s\n", slot->token->model);
	fprintf(stderr,"Slot token serialnr....: %s\n", slot->token->serialnr);

	size = strlen("slot_9999-id_") + strlen(keyid) * 2 + 1;
	ekeyid = malloc(size);
	snprintf(ekeyid,size-1,"slot_%d-id_",nslot);
	for(i=0,p=(char*)keyid;i<strlen(keyid);i++) {
		snprintf(part,sizeof(part),"%02x",*(p+i));
		strcat(ekeyid,part);
	}
	fprintf(stderr,"%s\n",ekeyid);

	PKCS11_release_all_slots(p11ctx, slots, nslots);
	PKCS11_CTX_unload(p11ctx);
	PKCS11_CTX_free(p11ctx);

	return ekeyid;
}

static void
parse_field(
	X509_NAME *name,
	char *p,
	char *q)
{
	char *eq,*f,*g;

	eq = strchr(p,'=');
	if (eq == NULL) {
		return;
	}
	if (q == NULL) {
		f = strndup(p,(eq - p));
		eq++;
		if (!X509_NAME_add_entry_by_txt(name,f,MBSTRING_ASC,eq,-1,-1,0)) {
			fprintf(stderr,"X509_NAME_add_entry_by_txt failure\n");
			exit(-1);
		}
		free(f);
	} else {
		if (eq > q) {
			return;
		}
		f = strndup(p,(eq - p));
		eq++;
		g = strndup(eq,(q - eq));
		if (!X509_NAME_add_entry_by_txt(name,f,MBSTRING_ASC,g,-1,-1,0)) {
			fprintf(stderr,"X509_NAME_add_entry_by_txt failure\n");
			exit(-1);
		}
		free(f);
		free(g);
	}
}

static X509_NAME *
parse_name(
	const char *subject)
{
	X509_NAME *name;
	char *p,*q;

	name = X509_NAME_new();
	if (name == NULL) {
		fprintf(stderr,"X509_NAME_new failure\n");
		exit(-1);
	}

	p = (char*)subject;
	do {
		q = strchr(p,',');
		parse_field(name,p,q);
		p = q + 1;
	} while (q != NULL);

	return name;
}

static int
tap11_make_csr(
	const char *p11lib,
	const char *pin,
	const char *keyid,
	const char *subject)
{
	ENGINE *e;
	EVP_PKEY *pk;
	X509_REQ *req;
	X509_NAME *name;
	BIO *err;
	char *ekeyid;

	ekeyid = get_engine_keyid(p11lib,pin,keyid);

	err = BIO_new_fp(stdout, BIO_NOCLOSE);

	ENGINE_load_dynamic();
	ENGINE_load_builtin_engines();
	e = ENGINE_by_id("dynamic");
	if (!e) {
		fprintf(stderr,"ENIGNE_by_id failure\n");
		return -1;
	}
	if(!ENGINE_ctrl_cmd_string(e, "SO_PATH", ENGINE_PKCS11_PATH, 0)||
	   !ENGINE_ctrl_cmd_string(e, "ID", "pkcs11", 0) ||
	   !ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1", 0) ||
	   !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0) ||
	   !ENGINE_ctrl_cmd_string(e, "MODULE_PATH", p11lib, 0) ||
	   !ENGINE_ctrl_cmd_string(e, "PIN", pin, 0) ) {
			fprintf(stderr,"ENGINE_ctrl_cmd_string failure\n");
			return -1;
	}
	if (!ENGINE_init(e)) {
		fprintf(stderr,"ENGINE_init failure\n");
		return -1;
	}

    if(!(pk = ENGINE_load_public_key(e, ekeyid, NULL, NULL))) {
		fprintf(stderr,"ENGINE_load_private_key failure\n");
		return -1;
    }

	req = X509_REQ_new();
	if (!X509_REQ_set_version(req,0L)) {
		/* version 1 */
		fprintf(stderr,"X509_REQ_set_version failure\n");
		return -1;
	}

	if (!X509_REQ_set_pubkey(req,pk)) {
		fprintf(stderr,"X509_REQ_set_pubkey failure\n");
		return -1;
	}

	name = parse_name(subject);
	if (!X509_REQ_set_subject_name(req, name)) {
		fprintf(stderr,"X509_REQ_set_subject_name failure\n");
		return -1;
	}
	X509_NAME_free(name);

	PEM_write_bio_X509_REQ(err,req);

	EVP_PKEY_free(pk);
	X509_REQ_free(req);
	BIO_free(err);
	free(ekeyid);

	return 0;
}

int 
main(int argc,char *argv[])
{
	if (argc < 5) {
		fprintf(stderr,"%% tap11_make_csr pkcs11.so pin keyid subject(ex C=JP,O=org,CN=cname)\n");
		return -1;
	}
	return tap11_make_csr(argv[1],argv[2],argv[3],argv[4]);
}
