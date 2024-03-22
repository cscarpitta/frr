// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 */

#ifndef _ZEBRA_SRV6_H
#define _ZEBRA_SRV6_H

#include <zebra.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "qobj.h"
#include "prefix.h"
#include <pthread.h>
#include <plist.h>

#define SRV6_SID_FORMAT_NAME_SIZE 512

/* Default config for SRv6 SID `usid-f3216` format */
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_NAME	      "usid-f3216"
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN    32
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_NODE_LEN     16
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_FUNCTION_LEN 16
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_ARGUMENT_LEN 0
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_LIB_START    0xE000
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_ELIB_START   0xFE00
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_ELIB_END     0xFEFF
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_WLIB_START   0xFFF0
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_WLIB_END     0xFFF7
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_EWLIB_START  0xFFF7

/* Default config for SRv6 SID `uncompressed` format */
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_NAME			"uncompressed"
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_BLOCK_LEN		40
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_NODE_LEN		24
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNCTION_LEN		16
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_ARGUMENT_LEN		0
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_EXPLICIT_RANGE_START 0xFF00
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNC_UNRESERVED_MIN	0x40

/* SID format type */
enum zebra_srv6_sid_format_type {
	ZEBRA_SRV6_SID_FORMAT_TYPE_UNSPEC = 0,
	/* SRv6 SID uncompressed format */
	ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED = 1,
	/* SRv6 SID compressed uSID format */
	ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID = 2,
};

/* SRv6 SID format */
struct zebra_srv6_sid_format {
	/* Name of the format */
	char name[SRV6_SID_FORMAT_NAME_SIZE];

	/* Format type: uncompressed vs compressed */
	enum zebra_srv6_sid_format_type type;

	/*
	 * Lengths of block/node/function/argument parts of the SIDs allocated
	 * using this format
	 */
	uint8_t block_len;
	uint8_t node_len;
	uint8_t function_len;
	uint8_t argument_len;

	union {
		/* Configuration settings for compressed uSID format type */
		struct {
			/* Start of the Local ID Block (LIB) range */
			uint32_t lib_start;

			/* Start/End of the Explicit LIB range */
			uint32_t elib_start;
			uint32_t elib_end;

			/* Start/End of the Wide LIB range */
			uint32_t wlib_start;
			uint32_t wlib_end;

			/* Start/End of the Explicit Wide LIB range */
			uint32_t ewlib_start;
		} usid;

		/* Configuration settings for uncompressed format type */
		struct {
			/* Start of the Explicit range */
			uint32_t explicit_start;
		} uncompressed;
	} config;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(zebra_srv6_sid_format);

/* SRv6 instance structure. */
struct zebra_srv6 {
	struct list *locators;

	/* Source address for SRv6 encapsulation */
	struct in6_addr encap_src_addr;

	/* SRv6 SID formats */
	struct list *sid_formats;
};

/* declare hooks for the basic API, so that it can be specialized or served
 * externally. Also declare a hook when those functions have been registered,
 * so that any external module wanting to replace those can react
 */

DECLARE_HOOK(srv6_manager_client_connect,
	    (struct zserv *client, vrf_id_t vrf_id),
	    (client, vrf_id));
DECLARE_HOOK(srv6_manager_client_disconnect,
	     (struct zserv *client), (client));
DECLARE_HOOK(srv6_manager_get_chunk,
	     (struct srv6_locator **loc,
	      struct zserv *client,
	      const char *locator_name,
	      vrf_id_t vrf_id),
	     (mc, client, keep, size, base, vrf_id));
DECLARE_HOOK(srv6_manager_release_chunk,
	     (struct zserv *client,
	      const char *locator_name,
	      vrf_id_t vrf_id),
	     (client, locator_name, vrf_id));


extern void zebra_srv6_locator_add(struct srv6_locator *locator);
extern void zebra_srv6_locator_delete(struct srv6_locator *locator);
extern struct srv6_locator *zebra_srv6_locator_lookup(const char *name);

void zebra_notify_srv6_locator_add(struct srv6_locator *locator);
void zebra_notify_srv6_locator_delete(struct srv6_locator *locator);

extern void zebra_srv6_init(void);
extern void zebra_srv6_terminate(void);
extern struct zebra_srv6 *zebra_srv6_get_default(void);
extern bool zebra_srv6_is_enable(void);

extern void srv6_manager_client_connect_call(struct zserv *client,
					     vrf_id_t vrf_id);
extern void srv6_manager_get_locator_chunk_call(struct srv6_locator **loc,
						struct zserv *client,
						const char *locator_name,
						vrf_id_t vrf_id);
extern void srv6_manager_release_locator_chunk_call(struct zserv *client,
						    const char *locator_name,
						    vrf_id_t vrf_id);
extern int srv6_manager_client_disconnect_cb(struct zserv *client);
extern int release_daemon_srv6_locator_chunks(struct zserv *client);

extern void zebra_srv6_encap_src_addr_set(struct in6_addr *src_addr);
extern void zebra_srv6_encap_src_addr_unset(void);

extern struct zebra_srv6_sid_format *
zebra_srv6_sid_format_alloc(const char *name);
extern void zebra_srv6_sid_format_free(struct zebra_srv6_sid_format *format);
extern void delete_zebra_srv6_sid_format(void *format);
void zebra_srv6_sid_format_register(struct zebra_srv6_sid_format *format);
void zebra_srv6_sid_format_unregister(struct zebra_srv6_sid_format *format);
struct zebra_srv6_sid_format *zebra_srv6_sid_format_lookup(const char *name);

#endif /* _ZEBRA_SRV6_H */
