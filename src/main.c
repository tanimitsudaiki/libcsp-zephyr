/*
 * Copyright (c) 2022 Space Cubics, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ztest.h>

static void test_assert(void)
{
	zassert_true(1, "1 was false");
	zassert_false(0, "0 was true");
	zassert_is_null(NULL, "NULL was not NULL");
	zassert_not_null("foo", "\"foo\" was NULL");
	zassert_equal(1, 1, "1 was not equal to 1");
	zassert_equal_ptr(NULL, NULL, "NULL was not equal to NULL");
}

void test_main(void)
{
	ztest_test_suite(tests,
			 ztest_unit_test(test_assert));

	ztest_run_test_suite(tests);
}
