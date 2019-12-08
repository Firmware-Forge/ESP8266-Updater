#include <Arduino.h>

class FFUpdates{
    private:
        String user_token;
        String fingerprint = "";
        const char* update_host = "firmwareforge.com";
        const char* update_url = "/devices/update";
        const char* finger_url = "/devices/fingerprint";
        const int https_port = 443;
        bool debug = false;
        
    public:

        /**
         * 
         */
        FFUpdates(String user_token);

        /**
         * 
         */
        FFUpdates(String user_token, bool debug);

        /**
         * 
         */
        ~FFUpdates();

        /**
         * 
         */
        void renewFingerprint();

        /**
         * 
         */
        void update();
};
