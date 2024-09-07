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

ZTEST(buffer, test_buffer_over_allocate)
{
	csp_packet_t *packets[CSP_BUFFER_COUNT];
	csp_packet_t *p;
	int i;

	memset(packets, 0, sizeof(packets));

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		packets[i] = csp_buffer_get(0);
		zassert_true(packets[i] != NULL, NULL);
	}

	zassert_true(csp_buffer_remaining() == 0);
	p = csp_buffer_get(0);
	zassert_true(p == NULL, NULL);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		csp_buffer_free(packets[i]);
	}
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
}

ZTEST_SUITE(buffer, NULL, setup, NULL, NULL, NULL);
