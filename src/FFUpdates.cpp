#include "FFUpdates.h"
#include <bearssl/bearssl.h>
#include <bearssl/bearssl_block.h>
#include <bearssl/bearssl_hash.h>
#include <ESP8266httpUpdate.h>

FFUpdates::FFUpdates() : user_token{"Not Set"}, user_secret{"Not Set"}, token_SHA256{"Not Set"}{
  // do nothing, variables are initialized in the initialization list
}

FFUpdates::FFUpdates(String user_token, String user_secret) : user_token{user_token}, user_secret{user_secret}{
   FFUpdates::token_SHA256 = FFUpdates::calculate_sha256(user_token, user_secret);
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

void FFUpdates::renew_fingerprint(){

    WiFiClient client;
    // BearSSL::WiFiClientSecure client;

    // encryption block contexts
    br_aes_gen_ctrcbc_keys keys;
    br_eax_context eax_context;

    String message;
    String buffer;
    String challenge_token;
    String new_fingerprint;
    String nonce;
    String tag;
    String calculated_tag_str;
    byte nonce_bytes[16];           // nonce from the server comes as 32 chars, but is hex, so actual length is 16. 
    byte challenge_token_bytes[80]; // the challenge token from the server is 160 chars long, but is hex, so actual size is 80.
    byte tag_bytes[16];             // tag from the server comes as 32 chars, but is hex, so actual length is 16.
    byte calculated_tag[16]; 


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
            if(found > 4) break;  // once we find all that we care about, end.
            if (message[i] != '\n') buffer += message[i];
            else{
                if(buffer.startsWith("nonce")){ 
                    nonce = buffer.substring(7);
                    nonce.remove(nonce.length() - 1);
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
                else if(buffer.startsWith("tag")){
                    tag = buffer.substring(5);
                    tag.remove(tag.length() - 1);
                    found ++;
                } 
                buffer = ""; // reset buffer for next run
            }
        }
    if(FFUpdates::debug) Serial.println(message); // what we got back from the server
    // convert the hex values we got from the server into uints and place them in the arrays.
    FFUpdates::hex_to_bytes(challenge_token, challenge_token_bytes);
    FFUpdates::hex_to_bytes(nonce, nonce_bytes);
    FFUpdates::hex_to_bytes(tag, tag_bytes);
    
    // // decrypt the message
    br_aes_big_ctrcbc_vtable.init(&keys.vtable, FFUpdates::user_secret.c_str(), 32);
    br_eax_init(&eax_context, &keys.vtable);
    br_eax_reset(&eax_context, nonce_bytes, 16);
    br_eax_flip(&eax_context);
    br_eax_run(&eax_context, false, challenge_token_bytes, 64);
    br_eax_get_tag(&eax_context, calculated_tag);

    challenge_token = ""; // wipe and populate with the decrypted value
    for(uint i = 0; i < 64; i++){
            char current = (char)challenge_token_bytes[i];
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

    expected = FFUpdates::bytes_to_hex(outputbuf, 32);
    calculated_tag_str = bytes_to_hex(calculated_tag, 32, 16);

    // if the current token hash equals the one the server replied with and the tags match
    if (expected == challenge_token && calculated_tag_str == tag){  
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
            Serial.print("Calculated tag: ");
            Serial.println(calculated_tag_str);
            Serial.print("Excpected tag: ");
            Serial.println(tag);
        }
    }
}

void FFUpdates::update(){
    if(FFUpdates::fingerprint == "") FFUpdates::renew_fingerprint(); // get the current fingerprint if this is our first run.

    if(!FFUpdates::handle_update()){
        Serial.println("Updated failed, renewing fingerprint.");
        FFUpdates::renew_fingerprint();
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

String FFUpdates::bytes_to_hex(byte* array, size_t length){
    String hex = "";
    for(uint i = 0; i < length; i ++){
        if(array[i] < 16) hex += ("0" + String(array[i], HEX)); // ensures we use two hex values to represent each block
        else hex += String(array[i], HEX);
    }
    return hex;
}

String FFUpdates::bytes_to_hex(byte* array, size_t length, uint8 starting_pos){
    String hex = "";
    for(uint i = starting_pos; i < length; i ++){
        if(array[i] < 16) hex += ("0" + String(array[i], HEX)); // ensures we use two hex values to represent each block
        else hex += String(array[i], HEX);
    }
    return hex;
}

void FFUpdates::hex_to_bytes(String hex, byte* buffer){
    int index = 0;
    for(uint i = 0; i < hex.length(); i += 2, index ++){
        char value[2];
        value[0] = hex[i];
        value[1] = hex[i + 1];
        buffer[index] = strtol(value, NULL, 16);
    }
}

uint32_t calculateCRC32(const uint8_t *data, size_t length) {
  uint32_t crc = 0xffffffff;
  while(length--) {
    uint8_t c = *data++;
    for(uint32_t i = 0x80; i > 0; i >>= 1) {
      bool bit = crc & 0x80000000;
      if(c & i) {
        bit = !bit;
      }
      crc <<= 1;
      if(bit) {
        crc ^= 0x04c11db7;
      }
    }
  }
  return crc;
}

void FFUpdates::save_to_rtc(){
    FFUpdatesRTCData rtc_data;
    strcpy(rtc_data.fingerprint, FFUpdates::fingerprint.c_str());
    strcpy(rtc_data.token_SHA256, FFUpdates::token_SHA256.c_str());
    rtc_data.user_data_size = 0;
    rtc_data.user_crc32 = 0;
    rtc_data.crc32 = calculateCRC32(((uint8_t*) &rtc_data) + 4, sizeof(rtc_data) - 4);
    ESP.rtcUserMemoryWrite(0, (uint32_t*) &rtc_data, sizeof(rtc_data)); 
}
   
void FFUpdates::save_to_rtc(void* user_data, size_t length){
    FFUpdatesRTCData rtc_data;
    // updater data
    strcpy(rtc_data.fingerprint, FFUpdates::fingerprint.c_str());
    strcpy(rtc_data.token_SHA256, FFUpdates::token_SHA256.c_str());
    
    // user data
    rtc_data.user_data_size = length;
    rtc_data.user_crc32 = calculateCRC32((uint8_t *) user_data, length);

    // final crc
    rtc_data.crc32 = calculateCRC32(((uint8_t*) &rtc_data) + 4, sizeof(rtc_data) - 4);
    ESP.rtcUserMemoryWrite(0, (uint32_t*) &rtc_data, sizeof(rtc_data));
    // the offset is in blocks of 4 bytes, account for that here
    ESP.rtcUserMemoryWrite((sizeof(rtc_data)/4), (uint32_t*) user_data, length);
}

bool FFUpdates::restore_rtc_data(){
    FFUpdatesRTCData rtc_data;
    if(ESP.rtcUserMemoryRead(0, (uint32_t*) &rtc_data, sizeof(rtc_data))) {
        // Calculate the CRC of what we just read from RTC memory, but skip the first 4 bytes as that's the checksum itself.
        uint32_t crc = calculateCRC32( ((uint8_t*) &rtc_data) + 4, sizeof(rtc_data) - 4 );
        if(crc == rtc_data.crc32){
            Serial.println(crc);
            Serial.println(rtc_data.crc32);
            FFUpdates::set_fingerprint(rtc_data.fingerprint);
            FFUpdates::set_token_SHA256(rtc_data.token_SHA256);
            return true;
        }
    } 
    return false;
}
   
bool FFUpdates::restore_rtc_data(void* buffer){
    FFUpdatesRTCData rtc_data;
    if(ESP.rtcUserMemoryRead(0, (uint32_t*) &rtc_data, sizeof(rtc_data))) {
        // Calculate the CRC of what we just read from RTC memory, but skip the first 4 bytes as that's the checksum itself.
        uint32_t crc = calculateCRC32( ((uint8_t*) &rtc_data) + 4, sizeof(rtc_data) - 4 );
        if(crc == rtc_data.crc32){
            // restore updater data
            FFUpdates::set_fingerprint(rtc_data.fingerprint);
            FFUpdates::set_token_SHA256(rtc_data.token_SHA256);
            
            // crc of user data, do the crc of all of it because its crc was stored in the rtcdata struct
            // the offset is in blocks of 4 bytes, account for that here
            if(ESP.rtcUserMemoryRead((sizeof(rtc_data)/4), (uint32_t*) buffer, rtc_data.user_data_size)) {
                crc = calculateCRC32( ((uint8_t*) buffer),  rtc_data.user_data_size);
                if(crc == rtc_data.user_crc32) return true; // we have passed the crc check on both blocks of data, success.

                else Serial.println("Failed at user data crc") ;
            }else Serial.println("Failed at user data read") ;
        }else Serial.println("Failed at rtc data crc") ;
    } else Serial.println("Failed at rtc data read") ;
    return false;
}

String FFUpdates::calculate_sha256(String user_token, String user_secret){
    br_sha256_context ctx;
    uint8_t outputbuf[32];
    String expect = ""; // wipe it for reuse

    // calculate sha256 using BearSSL builtins.
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, user_token.c_str(), 32);
    br_sha256_update(&ctx, user_secret.c_str(), 32);
    br_sha256_out(&ctx, outputbuf);
    return FFUpdates::bytes_to_hex(outputbuf, 32);
}
