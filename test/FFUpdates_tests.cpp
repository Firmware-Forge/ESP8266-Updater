#include <Arduino.h>
#include <FFUpdates>
#include <unity.h>

// void setUp(void) {
// // set stuff up here
// }

// void tearDown(void) {
// // clean stuff up here
// }

void test_set_get_user_token(void) {
    FFUpdates updater;
    updater.set_user_token("test_token");
    TEST_ASSERT_EQUAL("test_token", updater.get_user_token());
    updater.~FFUpdates();
}

void setup() {
    // NOTE!!! Wait for >2 secs
    // if board doesn't support software reset via Serial.DTR/RTS
    delay(2000);
    UNITY_BEGIN();    // IMPORTANT LINE!
    RUN_TEST(test_set_get_user_token);
    UNITY_END(); // stop unit testing
}
