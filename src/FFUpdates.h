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
        String device_token;
        String fingerprint = "";
        String token_SHA256;
        byte key[17];
        const char* update_host = "firmwareforge.com";
        const char* update_url = "/devices/update";
        const char* finger_url = "/devices/fingerprint";
        const int https_port = 443;
        bool debug = false;
        
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
         * @param device_token
         *        The token provided to the user for the specific device, can be found on the devices page on the device's card.
         * 
         */
        FFUpdates(String user_token, String device_token);

        /**
         * Destructor for the FFUpdates class.
         */
        ~FFUpdates();

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
         */ 
        void set_user_token(String user_token);

        /**
         * Gets the device token.
         * 
         * @return device token
         */ 
        String get_device_token();

        /**
         * Sets the device token.
         */ 
        void set_device_token(String device_token);

        /**
         * Returns the token_SHA256 hash.
         * 
         * @return the stored token hash.
         */
        String get_token_SHA256();

        /**
         * Sets the token_SHA256 hash.
         */ 
        void set_token_SHA256(String user_token);

        /**
         * Prints the sha256 has that the device has calculated. Meant more for debugging than for user usage.
         */
        void print_SHA256();

        /**
         * Gets the encryption key. Please note that you should iterate through this pointer and store the values
         * as a byte array. Storing this pointer in memory will not preserve the data through a reset as the 
         * pointer will be pointing to empty memory. The length of the key is 17.
         * 
         * @return encryption key pointer
         */
        byte* get_encryption_key();

        /**
         * Sets the encryption key.
         * 
         * @param key byte array pointer.
         */
        void set_encryption_key(byte* key);

        /**
         * Gets the stored server fingerprint. 
         * 
         * @return the stored fingerprint.
         */
        String get_fingerprint();

        /**
         * Sets the current server fingerprint.
         */ 
        void set_fingerprint(String user_token);

        /**
         * Asks the server for it's ssl certificate's sha1 fingerprint.
         * 
         * The certificate will change every so often due to it expiring, in that event,
         * the device needs to grab the new one so that it may communicate over https. To do this,
         * the device will ask the serverfor its certificate fingerprint and for a challenge token. This token
         * is the sha256 hash value of the device's token combined with the device owner's user token. Both the device
         * and the server will know this value and can calculate it independent of one another. If the hash passed
         * from the server matches what the device has calculated, the fingerprint is accepted and will be used to establish
         * secure communicates with the authentic server. This hash is transmitted in encrypted form using AES128 in CBC mode.
         * 
         * The user never needs to call this funciton directly, update will call it in the event that the fingerprint has changed.
         * This function has been left as public so that the user can call this if they ever choose to, although there is really no
         * reason to.
         */
        void renewFingerprint();

        /**
         * Checks to see if there is an update available for the device. If there is, the update is downloaded and applied. Otherwise,
         * its business as usual. 
         * 
         * The user is required to determine the update interval. For instance, if you want to check for an update 5 times an hour, then
         * you would need to implement a clock function that calles update 5 times an hour.
         */
        void update();
};
