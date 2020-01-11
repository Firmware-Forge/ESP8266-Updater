#include <ESP8266WiFi.h>
#include <FFUpdates.h>

const char* ssid = "SSID";
const char* password = "PASSWORD";
const String user_token = "USER_TOKEN";
const String device_token = "DEVICE_TOKEN";

FFUpdates updater(user_token, device_token);  // instantiate the updater
// FFUpdates updater(user_token, device_token, true); // enables debugging, this should not be enabled for production use.

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
  Serial.println("new lib");
  updater.update(); // check for an update, apply it if one exists.
  delay(5000);
}
