/*
 * Copyright (c) 2024 Space Cubics, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <csp/csp.h>

static void *setup(void)
{
	csp_init();
	return NULL;
}

/* test to get and free buffer (using csp_buffer_free) */
ZTEST(buffer, test_buffer_count)
{
	csp_packet_t *packets[CSP_BUFFER_COUNT];
	int i;

	memset(packets, 0, sizeof(packets));

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		packets[i] = csp_buffer_get(0);
		zassert_true(packets[i] != NULL, NULL);
	}

	zassert_true(csp_buffer_remaining() == 0);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		csp_buffer_free(packets[i]);
	}

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);
}

/* test when the buffer limit is reached (using csp_buffer_free) */
ZTEST(buffer, test_buffer_over_allocate)
{
	csp_packet_t *packets[CSP_BUFFER_COUNT];
	csp_packet_t *p;
	int i;
	uint8_t buffer_out = csp_dbg_buffer_out;

	memset(packets, 0, sizeof(packets));

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		packets[i] = csp_buffer_get(0);
		zassert_true(packets[i] != NULL, NULL);
	}

	zassert_true(csp_buffer_remaining() == 0);
	p = csp_buffer_get(0);
	zassert_true(p == NULL, NULL);
	zassert_equal(csp_dbg_buffer_out, (buffer_out+1));

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		csp_buffer_free(packets[i]);
	}
}

/* test to get and free buffer (using csp_buffer_get_isr) */
ZTEST(buffer, test_buffer_count_isr)
{
	csp_packet_t *packets[CSP_BUFFER_COUNT];
	int i;

	memset(packets, 0, sizeof(packets));

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		packets[i] = csp_buffer_get_isr(0);
		zassert_true(packets[i] != NULL, NULL);
	}

	zassert_true(csp_buffer_remaining() == 0);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		csp_buffer_free_isr(packets[i]);
	}

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);
}

/* test when the buffer limit is reached (using csp_buffer_get_isr) */
ZTEST(buffer, test_buffer_over_allocate_isr)
{
	csp_packet_t *packets[CSP_BUFFER_COUNT];
	csp_packet_t *p;
	int i;
	uint8_t buffer_out = csp_dbg_buffer_out;

	memset(packets, 0, sizeof(packets));

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		packets[i] = csp_buffer_get_isr(0);
		zassert_true(packets[i] != NULL, NULL);
	}

	zassert_true(csp_buffer_remaining() == 0);
	p = csp_buffer_get_isr(0);
	zassert_true(p == NULL, NULL);
	zassert_equal(csp_dbg_buffer_out, (buffer_out+1));

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		csp_buffer_free_isr(packets[i]);
	}

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);
}

/* test to free corrupted buffer */
ZTEST(buffer, test_buffer_free_error_corrupt_buffer)
{
	csp_packet_t packet;

	memset(&packet, 0, sizeof(csp_packet_t));

	csp_dbg_errno = 0;
	csp_buffer_free(&packet);
	zassert_equal(csp_dbg_errno, CSP_DBG_ERR_CORRUPT_BUFFER);
	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	csp_dbg_errno = 0;
	csp_buffer_free_isr(&packet);
	zassert_equal(csp_dbg_errno, CSP_DBG_ERR_CORRUPT_BUFFER);
	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	/* reset error flag */
	csp_dbg_errno = 0;
}

/* test to free a freed buffer */
ZTEST(buffer, test_buffer_free_error_already_free)
{
	csp_packet_t *packet;

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	packet = csp_buffer_get(0);
	zassert_not_null(packet);

	csp_dbg_errno = 0;
	csp_buffer_free(packet);
	zassert_equal(csp_dbg_errno, 0);
	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	csp_dbg_errno = 0;
	csp_buffer_free(packet);
	zassert_equal(csp_dbg_errno, CSP_DBG_ERR_ALREADY_FREE);
	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);
	
	csp_dbg_errno = 0;
	csp_buffer_free_isr(packet);
	zassert_equal(csp_dbg_errno, CSP_DBG_ERR_ALREADY_FREE);
	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	/* reset error flag */
	csp_dbg_errno = 0;
}

/* test for freeing buffer with invalid reference counter */
ZTEST(buffer, test_buffer_free_error_refcount)
{
	csp_packet_t *packet;

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	packet = csp_buffer_get(0);
	zassert_not_null(packet);

	csp_buffer_refc_inc(packet);

	csp_dbg_errno = 0;
	csp_buffer_free(packet);
	zassert_equal(csp_dbg_errno, CSP_DBG_ERR_REFCOUNT);

	csp_buffer_refc_inc(packet);
	
	csp_dbg_errno = 0;
	csp_buffer_free_isr(packet);
	zassert_equal(csp_dbg_errno, CSP_DBG_ERR_REFCOUNT);

	/* Free buffer */
	csp_dbg_errno = 0;
	csp_buffer_free(packet);
	zassert_equal(csp_dbg_errno, 0);
	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);
}

/* test for buffer clone */
ZTEST(buffer, test_buffer_clone)
{
	int buffer_size = CSP_BUFFER_COUNT / 2;
	int i, j;
	csp_packet_t *packets[buffer_size];
	csp_packet_t *clone[buffer_size];

	memset(packets, 0, sizeof(packets));

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	for (i = 0; i < buffer_size; i++) {
		packets[i] = csp_buffer_get(0);
		zassert_true(packets[i] != NULL, NULL);
	}

	for (i = 0; i < buffer_size; i++) {
		clone[i] = csp_buffer_clone(packets[i]);
		printf("packets[%d]=%p clone[%d]=%p\n", i, packets[i], i, clone[i]);
		zassert_equal(clone[i]->length, packets[i]->length);
		zassert_equal(clone[i]->id.pri, packets[i]->id.pri);
		zassert_equal(clone[i]->id.flags, packets[i]->id.flags);
		zassert_equal(clone[i]->id.src, packets[i]->id.src);
		zassert_equal(clone[i]->id.dst, packets[i]->id.dst);
		zassert_equal(clone[i]->id.dport, packets[i]->id.dport);
		zassert_equal(clone[i]->id.sport, packets[i]->id.sport);
		zassert_equal(clone[i]->next, packets[i]->next);
		for (j = 0; j < CSP_PACKET_PADDING_BYTES; j++) {
			zassert_equal(clone[i]->header[j], packets[i]->header[j]);
		}
		for (int j = 0; j < CSP_BUFFER_SIZE; j++) {
			zassert_equal(clone[i]->data[j], packets[i]->data[j]);
		}
	}

	for (i = 0; i < buffer_size; i++) {
		csp_buffer_free(packets[i]);
		csp_buffer_free(clone[i]);
	}

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);
}

/* test when passing invalid arguments to clone function */
ZTEST(buffer, test_buffer_clone_invalid_arg)
{
	csp_packet_t *clone;
	
	clone = csp_buffer_clone(NULL);
	zassert_is_null(clone);
}

/* test when cloning fails */
ZTEST(buffer, test_buffer_clone_limit_error)
{
	csp_packet_t *packets[CSP_BUFFER_COUNT];
	csp_packet_t *clone;
	int i;

	memset(packets, 0, sizeof(packets));

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		packets[i] = csp_buffer_get(0);
		zassert_true(packets[i] != NULL, NULL);
	}

	clone = csp_buffer_clone(packets[0]);
	zassert_is_null(clone);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		csp_buffer_free(packets[i]);
	}

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);
}

/* test when invalid arguments are given */
ZTEST(buffer, test_buffer_refc_inc_error_invalid_pointer)
{
	csp_dbg_errno = 0;
	csp_buffer_refc_inc(NULL);
	zassert_equal(csp_dbg_errno, CSP_DBG_ERR_INVALID_POINTER);

	/* reset error flag */
	csp_dbg_errno = 0;
}

/* test to reference corrupted buffer */
ZTEST(buffer, test_buffer_refc_inc_error_corrupt_buffer)
{
	csp_packet_t packet;

	memset(&packet, 0, sizeof(csp_packet_t));

	csp_dbg_errno = 0;
	csp_buffer_refc_inc(&packet);
	zassert_equal(csp_dbg_errno, CSP_DBG_ERR_CORRUPT_BUFFER);

	/* reset error flag */
	csp_dbg_errno = 0;
}

ZTEST_SUITE(buffer, NULL, setup, NULL, NULL, NULL);
