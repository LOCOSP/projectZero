# Goal
This project is an 2-board evil twin. It's based on:
- ESP32C5 (main CLI steering, deauth and password verification)
- ESP32 (evil twin captive portal)

It provides CLI and in future will provide an Flipper Zero app running captive portal and password verification.

![alt text](image-10.png)

# Features
Deauthenticates more than one network, including 5GHz on very high channels. Uses PH country code. 

Passes twin network name to ESP32 over ESP-NOW. Sets uo portal and collected password is passed back to C5 for verification. 

If verification is succesfull, deauth attack is stopped.

# Usage
CLI supports up/down arrows and TAB autocompletion. 
Typical usage would be:
scan_networks
select_networks 1 4
start_evil_twin

Please note order of selected networks is important. While all of them will be deauth'ed, the first one will additionally give name to an evil twin.

# Screenshots

On iPhone, Twin network should look like below. Note an invisible character has been added to network name to avoid grouping.

![alt text](image-1.png)

In CLI mode, successful attack should look like below. Note deauth stops as soon as password is verified.

![alt text](image-9.png)

# Deployment to boards
It's all about MACs! C5 needs to know ESP32 mac and vice versa. At the moment you need to modify it straight in the code.

## Initial deployment to ESP32
Use ArduinoIDE and open EvilTwin_slave.ino file.

Side note: When uploading code to ESP32C3 (or S3) remember to set USB CDC On Boot to Enabled - otherwise you will not see any serial:

![alt text](image-2.png)

Next, after starting up it will print it's MAC in Serial Monitor:

![alt text](image-3.png)
Note it down. 

## Initial deployment to ESP32-C5
Use ESP-IDF. Open Folder ESP32C5 and then click Open:

![alt text](image-4.png) 


Next, build, flash and monitor:

![alt text](image-5.png)

After it starts, grab the MAC address of C5 from the logs:

![alt text](image-6.png)

## MAC code updates
Now, in Arduino enter C5 MAC address (in hex form of byte array):

![alt text](image-7.png)

Next, in ESP-IDF in main.c on top enter ESP32 MAC address:

![alt text](image-8.png)

# Now recompile and flash both boards again.
They should become aware of each other and able to communicate over ESP-NOW.