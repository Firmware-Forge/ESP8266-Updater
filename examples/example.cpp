#include <ESP8266WiFi.h>
#include <FFUpdates.h>

const char* ssid = "SSID";
const char* password = "PASSWORD";
const String user_token = "USER_TOKEN";
const String user_secret = "USER_SECRET";

FFUpdates updater(user_token, user_secret);  // instantiate the updater

void setup() {
    Serial.begin(9600);
    Serial.println();
    Serial.print("connecting to ");
    Serial.println(ssid);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println();
    Serial.println("WiFi connected");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
}

void loop() {
    Serial.println("Checking for an update");
    updater.update(); // check for an update, apply it if one exists.
    delay(5000);  // check once every 5 seconds.
}
