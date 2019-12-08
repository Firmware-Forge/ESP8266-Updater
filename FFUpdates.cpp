#include "FFUpdates.h"
#include <WiFiClientSecure.h>
#include <ESP8266httpUpdate.h>

FFUpdates::FFUpdates(String user_token){
    FFUpdates::user_token = user_token;
}

FFUpdates::FFUpdates(String user_token, bool debug){
    FFUpdates::user_token = user_token;
    FFUpdates::debug = debug;
}

FFUpdates::~FFUpdates(){

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
            Serial.println(FFUpdates::user_token);
            found++;
        }
        else if(buffer.startsWith("sha-1")){ 
            new_fingerprint = buffer.substring(7);
            new_fingerprint.remove(new_fingerprint.length() - 1);
            Serial.println(new_fingerprint);
            found ++;
        }
        buffer = "";
        }
    }

    if (FFUpdates::user_token == challenge_token){  // if the current user token equals the one the server replied with
        Serial.println("Fingerprint updated!");     // update the fingerprint
        FFUpdates::fingerprint = new_fingerprint;
        if(FFUpdates::debug) Serial.println(fingerprint);
    }else{
        Serial.println("An error occured :(");
        Serial.println(FFUpdates::user_token.length());
        Serial.println(challenge_token.length());
    }
}

void FFUpdates::update(){
    WiFiClientSecure client;
    client.setInsecure();
    char fingerprintcopy[FFUpdates::fingerprint.length()];
    FFUpdates::fingerprint.toCharArray(fingerprintcopy, FFUpdates::fingerprint.length());

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
