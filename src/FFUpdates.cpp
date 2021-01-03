#include "FFUpdates.h"
#include <bearssl/bearssl.h>
#include <bearssl/bearssl_block.h>
#include <bearssl/bearssl_hash.h>
#include <ESP8266httpUpdate.h>

FFUpdates::FFUpdates() : user_token{"Not Set"}, user_secret{"Not Set"}, token_SHA256{"Not Set"}{
  // do nothing, variables are initialized in the initialization list
}

FFUpdates::FFUpdates(String user_token, String user_secret) : user_token{user_token}, user_secret{user_secret}{
    br_sha256_context ctx;
    uint8_t outputbuf[32];
    String expect = ""; // wipe it for reuse

    // calculate sha256 using BearSSL builtins.
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, user_token.c_str(), 32);
    br_sha256_update(&ctx, user_secret.c_str(), 32);
    br_sha256_out(&ctx, outputbuf);

    for(int i = 0; i < 32; i ++){
        if(outputbuf[i] < 16) expect += ("0" + String(outputbuf[i], HEX)); // ensures we use two hex values to represent each block
        else expect += String(outputbuf[i], HEX);
    }
    FFUpdates::token_SHA256 = expect;
}

FFUpdates::~FFUpdates(){
    // Handled by the compiler
}

void FFUpdates::enable_debug(bool debug){
    FFUpdates::debug = debug;
    Serial.println("============================================");
    Serial.print("Firmware Forge Updates Library version ");
    Serial.println(FFUpdates::version);
    Serial.println("--------------------------------------------");
    Serial.println("|                                          |");
    Serial.println("|        ## ###   ##(((        //          |");
    Serial.println("|             ##  ((((((((((((////         |");
    Serial.println("|           # ##   (((((#                  |");
    Serial.println("|             # (( ((((((                  |");
    Serial.println("|                                          |");
    Serial.println("|      ######((((((((((((/////////////     |");
    Serial.println("|      #####((((((((((((////////////       |");
    Serial.println("|        ##((((((((((((/////////           |");
    Serial.println("|            ((((((((//////////            |");
    Serial.println("|                (((//////////             |");
    Serial.println("|            ((((((///////////////         |");
    Serial.println("|            (((((////////////////         |");
    Serial.println("|                                          |");
    Serial.println("--------------------------------------------");
    if(debug) Serial.println("Debug Enabled");
    else Serial.println("Debug Disabled");
    Serial.println("============================================");
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

void FFUpdates::print_SHA256(){
    Serial.println(FFUpdates::token_SHA256);
}

void FFUpdates::renewFingerprint(){

    WiFiClient client;
    // BearSSL::WiFiClientSecure client;

    // encryption block contexts
    br_aes_gen_ctrcbc_keys keys;
    br_eax_context eax_context;

    String message, buffer, challenge_token, new_fingerprint, iv;
    byte iv_int[16]; // iv from the server comes as 32 chars, but is hex, so actual length is 16. 
    byte challenge_token_int[80]; // the challenge token from the server is 160 chars long, but is hex, so actual size is 80.


    if(FFUpdates::debug){
        Serial.print("connecting to ");
        Serial.println(FFUpdates::update_host);
    }

    // client.setInsecure(); // allows us to connect without verifying the fingerprint.
    // if (!client.connect(FFUpdates::update_host, 443)) {
    //     Serial.println("connection failed");
    //     return; // we failed, nothing else to do.
    // }
   
    if (!client.connect(FFUpdates::update_host, 8000)) {
        Serial.println("connection failed");
        return; // we failed, nothing else to do.
    }
    
    if (FFUpdates::debug){
        Serial.print("requesting URL: ");
        Serial.println(FFUpdates::finger_url);
    }

    client.print(String("GET ") + FFUpdates::finger_url + " HTTP/1.1\r\n" +
                "Host: " + FFUpdates::update_host + "\r\n" +
                "MAC: " + WiFi.macAddress() + "\r\n\r\n");

    if(FFUpdates::debug) Serial.println("request sent");
    
   
    message = client.readString();
    
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
                buffer = ""; // reset buffer for next run
            }
        }
    if(FFUpdates::debug) Serial.println(message); // what we got back from the server
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
    
    // // decrypt the message
    br_aes_big_ctrcbc_vtable.init(&keys.vtable, FFUpdates::user_secret.c_str(), 32);
    br_eax_init(&eax_context, &keys.vtable);
    br_eax_reset(&eax_context, iv_int, 16);
    br_eax_flip(&eax_context);
    br_eax_run(&eax_context, false, challenge_token_int, 64);

    challenge_token = ""; // wipe and populate with the decrypted value
    for(uint i = 0; i < 64; i++){
            char current = (char)challenge_token_int[i];
            if(isControl(current) || !isPrintable(current)) break;
            else challenge_token += current;
    }

    // calculate the sha256 hash for verifying that the fingerprint was not tampered with
    br_sha256_context hash_ctx;
    uint8_t outputbuf[32];
    String expected = ""; // wipe it for reuse

    br_sha256_init(&hash_ctx);
    br_sha256_update(&hash_ctx, FFUpdates::token_SHA256.c_str(), 64);
    br_sha256_update(&hash_ctx, new_fingerprint.c_str(), 59);
    br_sha256_out(&hash_ctx, outputbuf);

    for(int i = 0; i < 32; i ++){
        if(outputbuf[i] < 16) expected += ("0" + String(outputbuf[i], HEX)); // ensures we use two hex values to represent each block
        else expected += String(outputbuf[i], HEX);
    }

    if (expected == challenge_token){  // if the current token hash equals the one the server replied with
        Serial.println("Fingerprint updated!");     // update the fingerprint
        FFUpdates::fingerprint = new_fingerprint;
        if(FFUpdates::debug) Serial.println(fingerprint);
    }else{
        Serial.println("An error occured, the tokens do not match.");
        if(FFUpdates::debug){
            Serial.print("Challenge token: ");
            Serial.println(challenge_token);
            Serial.print("Excpected token: ");
            Serial.println(expected);
        }
    }
}

void FFUpdates::update(){
    if(FFUpdates::fingerprint == "") FFUpdates::renewFingerprint(); // get the current fingerprint if this is our first run.

    if(!FFUpdates::handle_update()){
        Serial.println("Updated failed, renewing fingerprint.");
        FFUpdates::renewFingerprint();
        if(!FFUpdates::handle_update()) Serial.println("Updated failed.");
    }
    
}

bool FFUpdates::handle_update(){
    BearSSL::WiFiClientSecure client;
    client.setFingerprint(FFUpdates::fingerprint.c_str());
     
    t_httpUpdate_return ret = ESPhttpUpdate.update(client, FFUpdates::update_url, FFUpdates::user_token);
    switch(ret){
    case HTTP_UPDATE_FAILED:
        Serial.println("Firmware update failed.");
        return false;
    case HTTP_UPDATE_NO_UPDATES:
        Serial.println("No update needed.");
        return true;
    case HTTP_UPDATE_OK:
        Serial.println("[update] Update ok."); // may not be called since we reboot the ESP
        return true;
    default:
        return false;
        break;
    }
}
