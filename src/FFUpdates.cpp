#include "FFUpdates.h"
#include <WiFiClientSecure.h>
#include <ESP8266httpUpdate.h>
#include <SHA256.h>
#include "aes.hpp"

FFUpdates::FFUpdates() : user_token{"Not Set"}, user_secret{"Not Set"}, token_SHA256{"Not Set"}{
  // do nothing, variables are initialized in the initialization list
}

FFUpdates::FFUpdates(String user_token, String user_secret) : user_token{user_token}, user_secret{user_secret}{
    SHA256 token_hash;
    uint8_t value[32];
    String expect = ""; // wipe it for reuse

    token_hash.reset();
    token_hash.update(user_token.c_str(), strlen(user_token.c_str()));
    token_hash.update(user_secret.c_str(), strlen(user_secret.c_str()));
    token_hash.finalize(value, 32);

    for(int i = 0; i < 32; i ++){ // there are 32 values, but we process two at a time
        if(value[i] < 16) expect += ("0" + String(value[i], HEX)); // ensures we use two hex values to represent each block
        else expect += String(value[i], HEX);
    }
    FFUpdates::token_SHA256 = expect;

    // create the encryption key
    user_secret = ""; // wipe this for reuse
    for(int i = 0; i < 32; i++) user_secret += FFUpdates::user_secret[i]; // get the first 32 chars
    user_secret.toCharArray((char*)&key, user_secret.length() + 1);
}

FFUpdates::~FFUpdates(){
    //todo implement?
}

void FFUpdates::enable_debug(bool debug){
    FFUpdates::debug = debug;
}

String FFUpdates::get_user_token(){
    return FFUpdates::user_token;
}

void FFUpdates::set_user_token(String user_token){
    FFUpdates::user_token = user_token;
}

String FFUpdates::get_user_secret(){
    return FFUpdates::user_secret;
}

void FFUpdates::set_user_secret(String user_secret){
    FFUpdates::user_secret = user_secret;
}

String FFUpdates::get_token_SHA256(){
    return FFUpdates::token_SHA256;
}

void FFUpdates::set_token_SHA256(String token_SHA256){
    FFUpdates::token_SHA256 = token_SHA256;
}

String FFUpdates::get_fingerprint(){
    return FFUpdates::fingerprint;
}

void FFUpdates::set_fingerprint(String fingerprint){
    FFUpdates::fingerprint = fingerprint;
}

byte* FFUpdates::get_encryption_key(){
            return key;
}

void FFUpdates::set_encryption_key(byte* key){
    for(int i = 0; i < 17; i ++) FFUpdates::key[i] = key[i];
} 

void FFUpdates::print_SHA256(){
    Serial.println(FFUpdates::token_SHA256);
}

void FFUpdates::renewFingerprint(){
    WiFiClientSecure client; 
    String message, buffer, challenge_token, new_fingerprint, iv;
    byte iv_int[33], challenge_token_int[65]; // the strings are 32 and 64 chars long, but save a space for the null terminator

    if(FFUpdates::debug){
        Serial.print("connecting to ");
        Serial.println(FFUpdates::update_host);
    }
    
    client.setInsecure(); // allows us to connect without verifying the fingerprint.   // UNCOMMENT
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
            if(found > 3) break;  // once we find all that we care about, end.
            if (message[i] != '\n') buffer += message[i];
            else{
            if(buffer.startsWith("iv")){ 
                iv = buffer.substring(4);
                iv.remove(iv.length() - 1);
                found++;
            }
            else if(buffer.startsWith("sha-1")){ 
                new_fingerprint = buffer.substring(7);
                new_fingerprint.remove(new_fingerprint.length() - 1);
                found ++;
            }
            else if(buffer.startsWith("token")){ 
                challenge_token = buffer.substring(7);
                challenge_token.remove(challenge_token.length() - 1);
                found ++;
            }
            buffer = "";
            }
        }

    // convert the hex values we got from the server into uints and place them in the arrays.
    int index = 0;
    for(uint i = 0; i < challenge_token.length(); i += 2, index ++){
        char value[2];
        value[0] = challenge_token[i];
        value[1] = challenge_token[i + 1];
        challenge_token_int[index] = strtol(value, NULL, 16);
    }
    index = 0;
    for(uint i = 0; i < iv.length(); i += 2, index ++){
        char value[2];
        value[0] = iv[i];
        value[1] = iv[i + 1];
        iv_int[index] = strtol(value, NULL, 16);
    }

    // decrypt the message
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, FFUpdates::key, iv_int);
    AES_CBC_decrypt_buffer(&ctx, challenge_token_int, 64);

    challenge_token = ""; // wipe and populate with the decrypted value
    for(uint i = 0; i < 64; i++){
            char current = (char)challenge_token_int[i];
            if(isControl(current) || !isPrintable(current)) break;
            else challenge_token += current;
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
        Serial.println("No update needed.");
        break;
    case HTTP_UPDATE_OK:
        Serial.println("[update] Update ok."); // may not be called since we reboot the ESP
        break;
    }
}
