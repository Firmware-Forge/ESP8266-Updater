How it Works
============

Upon intialization, the updater creates a hash value composed of
the user token and device token, this hash is used to prove the 
authenticity of the server when we request a new ssl certificate
fingerprint from the server. When the server's certificate is 
renewed or the device is powered on, the process of getting the 
server's fingerprint is called upon. 

The hash is transmitted from the server
after being encrypted using AES with the device token as the key,
preventing a third party from knowing and using the hash to trick
your device. Pending that the decrypted hash matches what the 
device calculated locally, the new fingerprint is accepted and
used to verify that the server your device is talking to is indeed
Firmware Forge. 

Once the server fingerprint is set, the device will
check for an update and apply it if needed. The device will not
check for a new fingerprint unless it is either powered off 
(e.g. ESP Deep sleep or a power on reset) or the server's certificate
is renewed (occurs once every 90 days.) The device is free to check for
updates as frequently or infrequently as the user wishes, it is up to the
user to call the update function at the desired time intervals. Below is
a diagram to visualize the update process.

.. figure:: _static/update.svg
   :alt: Update function control flow diagram

   Update Function Control Flow Diagram
