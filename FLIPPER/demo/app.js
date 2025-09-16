// Flipper Zero Evil Twin Controller Application

class FlipperEvilTwinApp {
    constructor() {
        this.currentScreen = 'main-menu';
        this.selectedMenuIndex = 0;
        this.selectedNetworks = new Set();
        this.firstSelectedNetwork = null;
        this.selectedNetworkIndex = 0;
        this.isEvilTwinRunning = false;
        this.logInterval = null;
        this.logIndex = 0;
        
        // Network data
        this.networks = [
            {index: 0, rssi: -45, auth: 0, channel: 1, bssid: "28:37:2F:5F:C3:19", ssid: "---"},
            {index: 1, rssi: -65, auth: 3, channel: 8, bssid: "AC:22:05:83:C7:3F", ssid: "VMA84A66C-2.4"},
            {index: 2, rssi: -65, auth: 5, channel: 8, bssid: "AE:22:25:83:C7:3F", ssid: "Horizon Wi-Free"},
            {index: 3, rssi: -70, auth: 3, channel: 1, bssid: "C2:E6:47:8E:19:58", ssid: "Galaxy S22 AA2B"},
            {index: 4, rssi: -72, auth: 4, channel: 11, bssid: "00:14:BF:72:A8:DE", ssid: "NETGEAR_HOME"},
            {index: 5, rssi: -78, auth: 3, channel: 6, bssid: "F8:32:E4:88:53:2A", ssid: "UPC_WIFI_2G"}
        ];

        // Sample logs for Evil Twin simulation
        this.sampleLogs = [
            "I (1234) projectZero: Starting Evil Twin attack...",
            "I (1245) projectZero: Sending deauth frames to selected networks",
            "I (1256) projectZero: Creating fake AP: VMA84A66C-2.4",
            "I (1267) projectZero: Captive portal server started on 192.168.4.1",
            "I (1278) projectZero: Client connecting: 12:34:56:78:90:AB",
            "I (1289) projectZero: Deauth sent to client 12:34:56:78:90:AB",
            "I (1300) projectZero: Client connected to fake AP",
            "I (1311) projectZero: HTTP request captured from client",
            "I (1322) projectZero: Credentials intercepted: user@example.com",
            "I (1333) projectZero: Attack successful, saving data...",
            "I (1344) projectZero: New client probe: 34:56:78:90:AB:CD",
            "I (1355) projectZero: Sending beacon frames...",
            "I (1366) projectZero: DNS spoofing active",
            "I (1377) projectZero: HTTPS downgrade successful",
            "I (1388) projectZero: Password captured: ********"
        ];

        this.init();
    }

    init() {
        this.bindEvents();
        this.renderNetworks();
        this.updateScreen();
    }

    bindEvents() {
        // D-pad button events
        document.getElementById('btn-up').addEventListener('click', () => this.handleDpadUp());
        document.getElementById('btn-down').addEventListener('click', () => this.handleDpadDown());
        document.getElementById('btn-left').addEventListener('click', () => this.handleDpadLeft());
        document.getElementById('btn-right').addEventListener('click', () => this.handleDpadRight());
        document.getElementById('btn-ok').addEventListener('click', () => this.handleDpadOK());
        document.getElementById('btn-back').addEventListener('click', () => this.handleBack());

        // Keyboard events for better UX
        document.addEventListener('keydown', (e) => {
            switch(e.key) {
                case 'ArrowUp': this.handleDpadUp(); e.preventDefault(); break;
                case 'ArrowDown': this.handleDpadDown(); e.preventDefault(); break;
                case 'ArrowLeft': this.handleDpadLeft(); e.preventDefault(); break;
                case 'ArrowRight': this.handleDpadRight(); e.preventDefault(); break;
                case 'Enter': case ' ': this.handleDpadOK(); e.preventDefault(); break;
                case 'Escape': this.handleBack(); e.preventDefault(); break;
            }
        });

        // Start Evil Twin button
        document.getElementById('start-evil-twin').addEventListener('click', () => this.startEvilTwin());

        // Network item click events for direct interaction
        document.addEventListener('click', (e) => {
            if (e.target.closest('.network-item')) {
                const networkItem = e.target.closest('.network-item');
                const index = parseInt(networkItem.getAttribute('data-index'));
                this.selectedNetworkIndex = index;
                this.updateNetworkSelection();
                this.toggleNetworkSelection(index);
            }
        });
    }

    handleDpadUp() {
        this.addButtonFeedback('btn-up');
        
        if (this.currentScreen === 'main-menu') {
            this.selectedMenuIndex = Math.max(0, this.selectedMenuIndex - 1);
            this.updateMainMenu();
        } else if (this.currentScreen === 'scan-networks') {
            this.selectedNetworkIndex = Math.max(0, this.selectedNetworkIndex - 1);
            this.updateNetworkSelection();
        }
    }

    handleDpadDown() {
        this.addButtonFeedback('btn-down');
        
        if (this.currentScreen === 'main-menu') {
            this.selectedMenuIndex = Math.min(1, this.selectedMenuIndex + 1);
            this.updateMainMenu();
        } else if (this.currentScreen === 'scan-networks') {
            this.selectedNetworkIndex = Math.min(this.networks.length - 1, this.selectedNetworkIndex + 1);
            this.updateNetworkSelection();
        }
    }

    handleDpadLeft() {
        this.addButtonFeedback('btn-left');
    }

    handleDpadRight() {
        this.addButtonFeedback('btn-right');
    }

    handleDpadOK() {
        this.addButtonFeedback('btn-ok');
        
        if (this.currentScreen === 'main-menu') {
            if (this.selectedMenuIndex === 0) {
                // Skanowanie sieci
                this.sendUARTCommand('scan_networks');
                this.currentScreen = 'scan-networks';
                this.selectedNetworkIndex = 0;
                this.updateScreen();
            } else if (this.selectedMenuIndex === 1) {
                // Reboot
                this.sendUARTCommand('reboot');
                this.showRebootMessage();
            }
        } else if (this.currentScreen === 'scan-networks') {
            // Toggle selection of currently highlighted network
            this.toggleNetworkSelection(this.selectedNetworkIndex);
        }
    }

    handleBack() {
        this.addButtonFeedback('btn-back');
        
        if (this.currentScreen === 'scan-networks') {
            this.currentScreen = 'main-menu';
            this.selectedMenuIndex = 0;
            this.updateScreen();
        } else if (this.currentScreen === 'evil-twin-running') {
            this.stopEvilTwin();
            this.currentScreen = 'main-menu';
            this.selectedMenuIndex = 0;
            this.updateScreen();
        }
    }

    addButtonFeedback(buttonId) {
        const button = document.getElementById(buttonId);
        button.style.transform = 'scale(0.95)';
        setTimeout(() => {
            button.style.transform = '';
        }, 100);
    }

    updateScreen() {
        // Hide all screens
        document.querySelectorAll('.screen').forEach(screen => {
            screen.classList.remove('active');
        });
        
        // Show current screen
        document.getElementById(this.currentScreen).classList.add('active');
        
        if (this.currentScreen === 'main-menu') {
            this.updateMainMenu();
        } else if (this.currentScreen === 'scan-networks') {
            this.updateNetworkSelection();
            this.updateStartButton();
        }
    }

    updateMainMenu() {
        const menuItems = document.querySelectorAll('.menu-item');
        menuItems.forEach((item, index) => {
            item.classList.toggle('selected', index === this.selectedMenuIndex);
        });
    }

    renderNetworks() {
        const networksList = document.getElementById('networks-list');
        networksList.innerHTML = '';
        
        this.networks.forEach((network, index) => {
            const networkItem = document.createElement('div');
            networkItem.className = 'network-item';
            networkItem.setAttribute('data-index', index);
            networkItem.style.cursor = 'pointer';
            
            networkItem.innerHTML = `
                <div class="network-checkbox"></div>
                <span class="network-data">${network.rssi}</span>
                <span class="network-data">${network.auth}</span>
                <span class="network-data">${network.channel}</span>
                <span class="network-data">${network.bssid}</span>
                <span class="network-data">${network.ssid}</span>
            `;
            
            networksList.appendChild(networkItem);
        });
    }

    updateNetworkSelection() {
        const networkItems = document.querySelectorAll('.network-item');
        networkItems.forEach((item, index) => {
            // Update selection highlighting
            item.classList.toggle('selected', index === this.selectedNetworkIndex);
            
            // Update checkbox state
            const checkbox = item.querySelector('.network-checkbox');
            if (this.selectedNetworks.has(index)) {
                checkbox.classList.add('checked');
            } else {
                checkbox.classList.remove('checked');
            }
            
            // Update first selected marker
            if (this.firstSelectedNetwork === index && this.selectedNetworks.has(index)) {
                item.classList.add('first-selected');
            } else {
                item.classList.remove('first-selected');
            }
        });
    }

    toggleNetworkSelection(index) {
        const networkItem = document.querySelectorAll('.network-item')[index];
        const checkbox = networkItem.querySelector('.network-checkbox');
        
        if (this.selectedNetworks.has(index)) {
            // Unselect network
            this.selectedNetworks.delete(index);
            checkbox.classList.remove('checked');
            networkItem.classList.remove('first-selected');
            
            // If this was the first selected, reassign to next available
            if (this.firstSelectedNetwork === index) {
                if (this.selectedNetworks.size > 0) {
                    // Find the chronologically first remaining selected network
                    this.firstSelectedNetwork = Math.min(...this.selectedNetworks);
                } else {
                    this.firstSelectedNetwork = null;
                }
            }
        } else {
            // Select network
            this.selectedNetworks.add(index);
            checkbox.classList.add('checked');
            
            // Mark as first selected if it's the first one
            if (this.firstSelectedNetwork === null) {
                this.firstSelectedNetwork = index;
            }
        }
        
        // Update the visual representation
        this.updateNetworkSelection();
        this.updateStartButton();
    }

    updateStartButton() {
        const startButton = document.getElementById('start-evil-twin');
        startButton.disabled = this.selectedNetworks.size === 0;
    }

    startEvilTwin() {
        if (this.selectedNetworks.size === 0) return;
        
        // Send UART commands
        const selectedIndices = Array.from(this.selectedNetworks).join(' ');
        this.sendUARTCommand(`select_networks ${selectedIndices}`);
        this.sendUARTCommand('start_evil_twin');
        
        // Switch to running screen
        this.currentScreen = 'evil-twin-running';
        this.updateScreen();
        this.startLogSimulation();
    }

    startLogSimulation() {
        this.isEvilTwinRunning = true;
        this.logIndex = 0;
        const logsContainer = document.getElementById('logs-container');
        logsContainer.innerHTML = '';
        
        // Add initial log
        this.addLogEntry('I (29279) projectZero: Found ' + this.networks.length + ' APs.');
        this.addLogEntry('I (29279) projectZero: Index  RSSI  Auth  Channel  BSSID              SSID');
        
        // Add selected networks info
        this.selectedNetworks.forEach(index => {
            const network = this.networks[index];
            this.addLogEntry(`I (29289) projectZero:     ${network.index}   ${network.rssi}     ${network.auth}      ${network.channel}  ${network.bssid}  ${network.ssid}`);
        });
        
        this.addLogEntry('I (29300) projectZero: Selected networks: ' + Array.from(this.selectedNetworks).join(', '));
        
        // Start continuous log simulation
        this.logInterval = setInterval(() => {
            if (this.logIndex < this.sampleLogs.length) {
                this.addLogEntry(this.sampleLogs[this.logIndex]);
                this.logIndex++;
            } else {
                // Loop back to beginning with time offset
                this.logIndex = 0;
                const timeOffset = Math.floor(Math.random() * 1000) + 2000;
                const log = this.sampleLogs[this.logIndex].replace(/\d+/, timeOffset);
                this.addLogEntry(log);
                this.logIndex++;
            }
        }, 1500);
    }

    addLogEntry(logText) {
        const logsContainer = document.getElementById('logs-container');
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        logEntry.textContent = logText;
        
        logsContainer.appendChild(logEntry);
        
        // Auto-scroll to bottom
        logsContainer.scrollTop = logsContainer.scrollHeight;
    }

    stopEvilTwin() {
        this.isEvilTwinRunning = false;
        if (this.logInterval) {
            clearInterval(this.logInterval);
            this.logInterval = null;
        }
        this.addLogEntry('I (' + (Date.now() % 100000) + ') projectZero: Evil Twin stopped by user');
        this.sendUARTCommand('stop_evil_twin');
    }

    sendUARTCommand(command) {
        console.log(`[UART] Sending command: ${command}`);
        
        // Simulate UART response delay
        setTimeout(() => {
            console.log(`[UART] Command executed: ${command}`);
        }, 100);
    }

    showRebootMessage() {
        // Simple reboot simulation
        const screens = document.querySelectorAll('.screen');
        screens.forEach(screen => screen.style.display = 'none');
        
        const flipperScreen = document.querySelector('.flipper-screen');
        const rebootMsg = document.createElement('div');
        rebootMsg.innerHTML = `
            <div style="
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100%;
                color: white;
                text-align: center;
                font-size: 14px;
            ">
                <div>
                    <div>Rebooting...</div>
                    <div style="font-size: 10px; margin-top: 8px;">Please wait</div>
                </div>
            </div>
        `;
        
        flipperScreen.appendChild(rebootMsg);
        
        setTimeout(() => {
            flipperScreen.removeChild(rebootMsg);
            screens.forEach(screen => screen.style.display = '');
            this.currentScreen = 'main-menu';
            this.selectedMenuIndex = 0;
            this.selectedNetworks.clear();
            this.firstSelectedNetwork = null;
            this.updateScreen();
        }, 2000);
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new FlipperEvilTwinApp();
});