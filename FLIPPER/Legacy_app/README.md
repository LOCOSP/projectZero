This application is a modified clone written by Dag Nazty.

## Debugging UART Communication

If you're experiencing issues with ESP responses not showing up in the Flipper app:

1. **Check the debug log file**: `/ext/apps_data/evil_esp_debug.txt` on your SD card
   - This file contains ALL UART traffic with timestamps
   
2. **View console logs**: Connect Flipper via USB and check qFlipper console
   - Look for `[EvilEsp] RX:` messages showing received data
   - Check if responses are being filtered as echoes
   
3. **Test with sample firmware**: Upload `ESP_TEST_FIRMWARE.ino` to your ESP board
   - This sends properly formatted responses for all commands
   - Helps determine if issue is with ESP firmware or Flipper app

4. **Read the debug guide**: See `DEBUG_UART.md` for detailed troubleshooting

### Expected Response Format

The ESP board should send responses in one of these formats:

**For scan_networks:**
```
[INFO] Index,SSID,BSSID,Channel,Auth,RSSI,Frequency
[INFO] "0","MyNetwork","AA:BB:CC:DD:EE:FF","6","WPA2","-45","2.4GHz"
[INFO] Scan completed
```

**For select_networks:**
```
[INFO] Networks selected: 1, 2, 3
```

**For start_deauth:**
```
[INFO] Deauth attack started
```

All responses should end with `\n` (newline) and use 115200 baud rate. 
