package adr0017_parameterized_assertions

import rego.v1

test_rate_test_test_rate_allows if { count([true | some _, value in data.redops.rate_test.test_rate_allows; value == true]) == 3 }

test_rate_test_test_rate_denies_invalid_runtime if { count([true | some _, sub in data.redops.rate_test.test_rate_denies_invalid_runtime; some _, value in sub; value == true]) == 18 }

test_rate_test_test_rate_denies_invalid_limit if { count([true | some _, sub in data.redops.rate_test.test_rate_denies_invalid_limit; some _, value in sub; value == true]) == 16 }

test_rate_test_test_rate_denies_missing_runtime_field if { count([true | some _, value in data.redops.rate_test.test_rate_denies_missing_runtime_field; value == true]) == 2 }

test_rate_test_test_rate_denies_missing_limit if { count([true | some _, value in data.redops.rate_test.test_rate_denies_missing_limit; value == true]) == 2 }

test_rate_test_test_rate_denies_missing_input_sections if { count([true | some _, value in data.redops.rate_test.test_rate_denies_missing_input_sections; value == true]) == 4 }

test_breaker_test_test_breaker_allows if { count([true | some _, value in data.redops.breaker_test.test_breaker_allows; value == true]) == 2 }

test_breaker_test_test_breaker_denies_bad_threshold if { count([true | some _, value in data.redops.breaker_test.test_breaker_denies_bad_threshold; value == true]) == 8 }

test_breaker_test_test_breaker_denies_bad_or_tripped_counter if { count([true | some _, value in data.redops.breaker_test.test_breaker_denies_bad_or_tripped_counter; value == true]) == 9 }

test_breaker_test_test_breaker_denies_missing_input if { count([true | some _, value in data.redops.breaker_test.test_breaker_denies_missing_input; value == true]) == 6 }

test_window_test_test_timestamp_bounds if { count([true | some _, sub in data.redops.window_test.test_timestamp_bounds; some _, value in sub; value == true]) == 28 }

test_window_test_test_invalid_window if { count([true | some _, value in data.redops.window_test.test_invalid_window; value == true]) == 9 }

test_window_test_test_missing_input if { count([true | some _, value in data.redops.window_test.test_missing_input; value == true]) == 3 }
