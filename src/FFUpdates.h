#include <Arduino.h>

/**
 * Provides an abstraction layer for the user to update their device.
 * Piggy backs off of the ESP8266httpUpdate class. The additional functionality
 * provided by this library includes handling changes made to the server's
 * ssl certificate fingerpint. 
 */
class FFUpdates{
    private:
        String user_token;
        String user_secret;
        String token_SHA256;
        String fingerprint = "";
        const char* update_host = "192.168.1.30";             
        const char* update_url = "https://api.firmwareforge.com/devices/update/";
        const char* finger_url = "/devices/fingerprint/";
        const char* version = "0.33a";                    
        bool debug = false;

        /**
         * Handles the actual update operation. Connects to the server, flashes the firmware and such.
         * Will return true if we were able to connect to the server and no issues were experienced.
         * Otherwise we will return false so that we know we need to update the certificate fingerprint.
         * 
         * @return update success
         */ 
        bool handle_update();

        /**
         * Converts an array of bytes into the equivalent hex string.
         * 
         * @param array
         *        Byte array to convert
         * 
         * @param length
         *        length of the byte array  
         * 
         * @return hex string
         */ 
        String bytes_to_hex(byte* array, size_t length);

        /**
         * Converts an array of bytes into the equivalent hex string, starting at a specified position in the array.
         * 
         * @param array
         *        Byte array to convert
         * 
         * @param length
         *        length of the byte array 
         * 
         * @param starting_pos
         *        position to start the hex conversion at 
         * 
         * @return hex string
         */ 
        String bytes_to_hex(byte* array, size_t length, uint8 starting_pos);

        /**
         * Converts a hex array to an array of bytes.
         * 
         * @param hex
         *        The hex string to convert to bytes
         * @param buffer
         *        buffer to write the byte array to. This should be half the length of the hex string.
         */
        void hex_to_bytes(String hex, byte* buffer);

        /**
         * CRC calculation utility fucntion
         * 
         * @param data
         *        pointer to the data to calculate CRC over
         * @param length
         *        size of the data
         * @returns CRC of the data
         */ 
        uint32_t caculate_CRC32(const uint8_t *data, size_t length);
        
    public:
        /**
         * Default Constructor for the FFUpdates class. Creates the object but does not intialize any data.
         * Requires the user to provide the token_SHA256 and user_token via the set methods.
         */
        FFUpdates();

        /**
         *  Basic Constructor for the FFUpdates class, initializes object data such as token_SHA256.
         *
         * @param user_token
         *        The token provided to the user on their profile page.
         *        
         * @param user_secret
         *        The token provided to the user for the specific device, can be found on the devices page on the device's card.
         * 
         */
        FFUpdates(String user_token, String user_secret);

        /**
         * Destructor for the FFUpdates class.
         */
        ~FFUpdates();

        /**
         * Utility function for manually caluting the user hash.
         * 
         * @param user_token
         *        Firmware Forge User Token
         * @param user_secret
         *        Firmware Forge User Secret
         * @returns calculated SHA256 hash
         * 
         */ 
        String calculate_sha256(String user_token, String user_secret);

        /**
         * Enable/disable debug.
         * 
         * @param debug
         *        enable or disable debugging by passing true or false respectively.
         */ 
        void enable_debug(bool debug);

        /**
         * Returns the user token. 
         * 
         * @return the stored user token.
         */
        String get_user_token();

        /**
         * Sets the user token.
         * 
         * @param user_token
         *        Token provided to the user on their profile page.
         */ 
        void set_user_token(String user_token);

        /**
         * Gets the device token.
         * 
         * @return device token
         */ 
        String get_user_secret();

        /**
         * Sets the device token.
         * 
         * @param user_secret
         *        Secret provided to user on their profile page.
         */ 
        void set_user_secret(String user_secret);

        /**
         * Returns the token_SHA256 hash.
         * 
         * @return the stored token hash.
         */
        String get_token_SHA256();

        /**
         * Sets the token_SHA256 hash.
         * 
         * @param token_SHA256
         *        Previously calculated SHA256 hash of the user token and user secret.
         */ 
        void set_token_SHA256(String token_SHA256);

        /**
         * Prints the sha256 has that the device has calculated. Meant more for debugging than for user usage.
         */
        void print_SHA256();

        /**
         * Gets the stored server fingerprint. 
         * 
         * @return the stored fingerprint.
         */
        String get_fingerprint();

        /**
         * Sets the current server fingerprint.
         * 
         * @param fingerprint
         *        last known valid fingerprint of the SSL cert.
         */         
        void set_fingerprint(String fingerprint);

        /**
         * Asks the server for it's ssl certificate's sha1 fingerprint.
         * 
         * The certificate will change every so often due to it expiring, in that event,
         * the device needs to grab the new one so that it may communicate over https. To do this,
         * the device will ask the serverfor its certificate fingerprint and for a challenge token. This token
         * is the sha256 hash value of the device owner's user secret combined with the device owner's user token. Both the device
         * and the server will know this value and can calculate it independent of one another. If the hash passed
         * from the server matches what the device has calculated, the fingerprint is accepted and will be used to establish
         * secure communicates with the authentic server. This hash is transmitted in encrypted form using AES256 in CBC mode.
         * 
         * The user never needs to call this funciton directly, update will call it in the event that the fingerprint has changed.
         * This function has been left as public so that the user can call this if they ever choose to, although there is really no
         * reason to.
         */
        void renew_fingerprint();

        /**
         * Checks to see if there is an update available for the device. If there is, the update is downloaded and applied. Otherwise,
         * its business as usual. 
         * 
         * The user is required to determine the update interval. For instance, if you want to check for an update 5 times an hour, then
         * you would need to implement a clock function that calls update 5 times an hour.
         */
        void update();

        /**
         * Saves the updater data structure to rtc memory,
         * should be called prior to puting the ESP into deep sleep.
         */
        void save_to_rtc();

        /**
         * Saves the updater data structure as well as the passed user data structure to rtc memory,
         * should be called prior to puting the ESP into deep sleep. CRC validation is provided by this
         * function for the user data, so there is no need to calculate it and store it in the user data
         * structure. The size of the user data stucture must be a multplie of 4.
         * 
         * @param user_data
         *        pointer to a user specified struct containing user data that needs to be persisted across deep sleep.
         * 
         * @param length
         *        length in bytes of the user data structure.
         */
        void save_to_rtc(void* user_data, size_t length);

        /**
         * Restores the updater's data from rtc memory.
         * 
         * @returns true if data is restored succesfully (data is found and passes crc validation)
         */
        bool restore_rtc_data();

        /**
         * Restores the updater's data from rtc memory as well as the user's data.
         * 
         * @param buffer
         *        buffer to restore the user data to
         * @returns true if data is restored succesfully (data is found and passes crc validation)
         */
        bool restore_rtc_data(void* buffer);
};

typedef struct{
  // the size of this struct must be a multiple of 4
  uint32_t crc32;        // 4 bytes
  char token_SHA256[65]; // 65
  char fingerprint[60];  // 60
  int user_data_size;    // 4 bytes
  uint32_t user_crc32;   // 4 bytes
  char padding[3];       // 3 bytes
                         // 140 bytes total, leaving 372 bytes for the user to use.
} FFUpdatesRTCData;
