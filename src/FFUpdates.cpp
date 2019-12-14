#include "FFUpdates.h"
#include <WiFiClientSecure.h>
#include <ESP8266httpUpdate.h>
#include <SHA256.h>

FFUpdates::FFUpdates(String user_token, String device_token){
    FFUpdates::user_token = user_token;
    SHA256 token_hash;
    uint8_t value[32];
    String expect = ""; // wipe it for reuse

    token_hash.reset();
    token_hash.update(user_token.c_str(), strlen(user_token.c_str()));
    token_hash.update(device_token.c_str(), strlen(device_token.c_str()));
    token_hash.finalize(value, 32);

    for(int i = 0; i < 32; i ++){
        if(value[i] < 16) expect += ("0" + String(value[i], HEX)); // ensures we use two hex values to represent each block
        else expect += String(value[i], HEX);
    }
    FFUpdates::token_SHA256 = expect;
    
}

FFUpdates::FFUpdates(String user_token, String device_token, bool debug){
    FFUpdates::user_token = user_token;
    FFUpdates::debug = debug;
    SHA256 token_hash;
    uint8_t value[32];
    String expect = ""; // wipe it for reuse

    token_hash.reset();
    token_hash.update(user_token.c_str(), strlen(user_token.c_str()));
    token_hash.update(device_token.c_str(), strlen(device_token.c_str()));
    token_hash.finalize(value, 32);

    for(int i = 0; i < 32; i ++){
        if(value[i] < 16) expect += ("0" + String(value[i], HEX)); // ensures we use two hex values to represent each block
        else expect += String(value[i], HEX);
    }
    FFUpdates::token_SHA256 = expect;
}

FFUpdates::~FFUpdates(){

}

void FFUpdates::print_SHA256(){
    Serial.println(FFUpdates::token_SHA256);
}

void FFUpdates::renewFingerprint(){
    WiFiClientSecure client;
    String message, buffer, challenge_token, new_fingerprint; 

    if(FFUpdates::debug){
        Serial.print("connecting to ");
        Serial.println(FFUpdates::update_host);
    }
    
    client.setInsecure(); // allows us to connect without verifying the fingerprint.
    if (!client.connect(FFUpdates::update_host, FFUpdates::https_port)) {
        Serial.println("connection failed");
        return; // we failed, nothing else to do.
    }

    if (FFUpdates::debug){
        Serial.print("requesting URL: ");
        Serial.println(FFUpdates::update_url);
    }

    client.print(String("GET ") + FFUpdates::finger_url + " HTTP/1.1\r\n" +
                "Host: " + FFUpdates::update_host + "\r\n" +
                "MAC: " + WiFi.macAddress() + "\r\n\r\n");

    if(FFUpdates::debug) Serial.println("request sent");
    
    while (client.connected()) {
        message = client.readString();
    }

    if(FFUpdates::debug) Serial.println(message); // what we got back from the server
    
    int found = 0;
    for(unsigned int i = 0; i < message.length(); i++){
        if(found > 1) break;
        if (message[i] != '\n') buffer += message[i];
        else{
        if(buffer.startsWith("token")){ 
            challenge_token = buffer.substring(7);
            challenge_token.remove(challenge_token.length() - 1);
            found++;
        }
        else if(buffer.startsWith("sha-1")){ 
            new_fingerprint = buffer.substring(7);
            new_fingerprint.remove(new_fingerprint.length() - 1);
            found ++;
        }
        buffer = "";
        }
    }

    if (FFUpdates::token_SHA256 == challenge_token){  // if the current token hash equals the one the server replied with
        Serial.println("Fingerprint updated!");     // update the fingerprint
        FFUpdates::fingerprint = new_fingerprint;
        if(FFUpdates::debug) Serial.println(fingerprint);
    }else{
        Serial.println("An error occured, the tokens do not match.");
        if(FFUpdates::debug){
            Serial.print("Challenge token: ");
            Serial.println(challenge_token);
            Serial.print("Excpected token: ");
            Serial.println(FFUpdates::token_SHA256);
        }
    }
}

void FFUpdates::update(){
    // test the connnection
    t_httpUpdate_return ret = ESPhttpUpdate.update(FFUpdates::update_host,
                                        FFUpdates::https_port,
                                        FFUpdates::update_url,
                                        FFUpdates::user_token,
                                        FFUpdates::fingerprint);
    switch(ret) {
    case HTTP_UPDATE_FAILED:
        Serial.println("Update failed, attempting to renew server fingerprint.");
        FFUpdates::renewFingerprint();
        ret = ESPhttpUpdate.update(FFUpdates::update_host,
                                        FFUpdates::https_port,
                                        FFUpdates::update_url,
                                        FFUpdates::user_token,
                                        FFUpdates::fingerprint);
        switch(ret) {
        case HTTP_UPDATE_FAILED:
            Serial.println("Update failed, aborting.");
            break;
        case HTTP_UPDATE_NO_UPDATES:
            Serial.println("No update needed.");
            break;
        case HTTP_UPDATE_OK:
            Serial.println("[update] Update ok."); // may not be called since we reboot the ESP
            break;
        }
        break;
    case HTTP_UPDATE_NO_UPDATES:
        Serial.println("No update needed..");
        break;
    case HTTP_UPDATE_OK:
        Serial.println("[update] Update ok."); // may not be called since we reboot the ESP
        break;
    }
}
