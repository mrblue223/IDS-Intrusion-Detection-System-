const { ipcRenderer } = require('electron'); //

document.addEventListener('DOMContentLoaded', () => { //
    // UI Elements
    const tabs = { //
        home: document.getElementById('tab-home'), //
        logs: document.getElementById('tab-logs'), //
        signatures: document.getElementById('tab-signatures'), //
        status: document.getElementById('tab-status') //
    }; //

    const views = { //
        home: document.getElementById('home-view'), //
        logs: document.getElementById('logs-view'), //
        signatures: document.getElementById('signatures-view'), //
        status: document.getElementById('status-view') //
    }; //

    const signatureInput = document.getElementById('signature-input'); //
    const uploadBtn = document.getElementById('upload-btn'); //
    const uploadStatus = document.getElementById('upload-status'); //
    const alertsLog = document.getElementById('alerts-log'); //
    // const refreshAlertsBtn = document.getElementById('refresh-alerts'); // Removed for live logs
    const idsStatusText = document.getElementById('ids-status-text'); //
    const refreshStatusBtn = document.getElementById('refresh-status'); //

    // NEW: Live Log UI elements
    const startLiveLogButton = document.getElementById('startLiveLog');
    const stopLiveLogButton = document.getElementById('stopLiveLog');

    // Initial state: show home view
    let activeTab = 'home'; //
    showView(activeTab); //

    // --- Tab Switching Logic ---
    function showView(viewName) { //
        // Hide all views
        for (const key in views) { //
            views[key].classList.remove('active'); //
        } //
        // Deactivate all tabs
        for (const key in tabs) { //
            tabs[key].classList.remove('active'); //
        } //

        // Show the selected view and activate the corresponding tab
        views[viewName].classList.add('active'); //
        tabs[viewName].classList.add('active'); //
        activeTab = viewName; //
    } //

    tabs.home.addEventListener('click', () => showView('home')); //
    tabs.logs.addEventListener('click', () => showView('logs')); //
    tabs.signatures.addEventListener('click', () => showView('signatures')); //
    tabs.status.addEventListener('click', () => showView('status')); //


    // --- Signature Upload Logic ---
    uploadBtn.addEventListener('click', () => { //
        const signatures = signatureInput.value; //
        try { //
            // Basic JSON validation before sending
            JSON.parse(signatures); //
            uploadStatus.textContent = 'Uploading signatures...'; //
            uploadStatus.style.color = 'orange'; //
            ipcRenderer.send('upload-signatures', signatures); //
        } catch (e) { //
            uploadStatus.textContent = 'Invalid JSON format.'; //
            uploadStatus.style.color = 'red'; //
        } //
    }); //

    ipcRenderer.on('upload-status', (event, message) => { //
        uploadStatus.textContent = message; //
        if (message.includes('successful')) { //
            uploadStatus.style.color = 'green'; //
        } else if (message.includes('failed')) { //
            uploadStatus.style.color = 'red'; //
        } //
    }); //


    // --- Live Log Logic ---
    // Listen for incoming live log entries from the main process
    ipcRenderer.on('live-log-entry', (event, logEntry) => {
        console.log('Received log entry in renderer:', logEntry); // MODIFICATION: Added for debugging
        const logElement = document.createElement('div');
        logElement.textContent = logEntry;
        alertsLog.appendChild(logElement);
        // Automatically scroll to the bottom
        alertsLog.scrollTop = alertsLog.scrollHeight;
    });

    // Listen for live log status messages (e.g., connection status)
    ipcRenderer.on('live-log-status', (event, statusMessage) => {
        const statusElement = document.createElement('div');
        statusElement.textContent = `[STATUS] ${statusMessage}`;
        statusElement.style.fontWeight = 'bold';
        statusElement.style.fontStyle = 'italic';
        if (statusMessage.startsWith('ERROR')) {
            statusElement.style.color = 'red';
        } else {
            statusElement.style.color = '#888'; // Grey for general status
        }
        alertsLog.appendChild(statusElement);
        alertsLog.scrollTop = alertsLog.scrollHeight;
    });

    // Event listeners for live log buttons
    startLiveLogButton.addEventListener('click', () => {
        ipcRenderer.send('start-live-log');
    });

    stopLiveLogButton.addEventListener('click', () => {
        ipcRenderer.send('stop-live-log');
    });


    // --- IDS Status Logic ---
    async function getIdsStatus() { //
        try { //
            const status = await ipcRenderer.invoke('get-ids-status'); //
            idsStatusText.textContent = status; //
            idsStatusText.style.color = status.startsWith('ERROR') ? 'red' : 'green'; //

            // Placeholder for dashboard widgets (update with actual data if backend provides it)
            if (activeTab === 'home') { //
                document.getElementById('total-packets-count').textContent = 'N/A'; // Replace with actual value //
                document.getElementById('total-alerts-count').textContent = 'N/A'; // Replace with actual value //
            } //

        } catch (error) { //
            idsStatusText.textContent = `Status Error: ${error.message}`; //
            idsStatusText.style.color = 'red'; //
        } //
    } //

    refreshStatusBtn.addEventListener('click', getIdsStatus); //

    // Initial loads when app starts (for home and status views)
    getIdsStatus(); //
    // Refresh status periodically (for status page or background monitoring)
    setInterval(getIdsStatus, 5000); //
});