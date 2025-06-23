const { app, BrowserWindow, ipcMain } = require('electron');
const net = require('net'); // For TCP socket communication with C backend

let mainWindow;
const C_IDS_PORT = 8888; // Must match global_config.gui_listen_port in C code
const C_IDS_HOST = '127.0.0.1'; // Localhost

// Define a variable to hold the live log client socket
let liveLogClient = null;
let reconnectAttempt = 0;
const MAX_RECONNECT_ATTEMPTS = 10; // Or adjust as needed
const RECONNECT_DELAY_MS = 3000; // 3 seconds

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            nodeIntegration: true, // Be cautious with nodeIntegration in production
            contextIsolation: false // For simpler IPC, but contextIsolation is safer
        }
    });

    mainWindow.loadFile('index.html');

    // Open the DevTools.
    // Uncomment the line below to open DevTools for easier debugging
    mainWindow.webContents.openDevTools(); // MODIFICATION: Uncommented for debugging
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
    // Ensure the live log client is destroyed when the app closes
    if (liveLogClient) {
        liveLogClient.destroy();
        liveLogClient = null;
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

// --- START LIVE LOGGING LOGIC (MAIN PROCESS) ---

// Function to connect to the C IDS backend for live logs
function connectLiveLogClient() {
    // Prevent multiple simultaneous connections for live logs
    if (liveLogClient && !liveLogClient.destroyed && liveLogClient.readyState === 'open') {
        console.log('Live log client already connected.');
        return; // Already connected
    }

    // Handle max reconnection attempts to prevent infinite loops
    if (reconnectAttempt >= MAX_RECONNECT_ATTEMPTS) {
        console.error('Max reconnection attempts reached. Giving up.');
        if (mainWindow && !mainWindow.isDestroyed()) {
            // Inform the renderer process about the connection error
            mainWindow.webContents.send('live-log-status', 'ERROR: Max reconnection attempts reached. Live log stream stopped.');
        }
        liveLogClient = null;
        reconnectAttempt = 0; // Reset for next explicit start by user
        return;
    }

    console.log(`Attempting to connect live log client (attempt ${reconnectAttempt + 1})...`);
    liveLogClient = new net.Socket();
    let dataBuffer = ''; // Buffer to handle partial messages from the C backend

    // Event handler for successful connection to the C backend
    liveLogClient.connect(C_IDS_PORT, C_IDS_HOST, () => {
        console.log('Connected to C IDS backend for live log stream.');
        if (mainWindow && !mainWindow.isDestroyed()) {
            // Send a status message to the renderer indicating success
            mainWindow.webContents.send('live-log-status', 'Live log stream started.');
        }
        // IMPORTANT: Send the command to the C backend to start streaming logs
        liveLogClient.write('START_LOG_STREAM\n');
        reconnectAttempt = 0; // Reset attempts on successful connection
    });

    // Event handler for receiving data (log entries) from the C backend
    liveLogClient.on('data', (data) => {
        console.log('Raw data received from C backend:', data.toString()); // MODIFICATION: Added for debugging
        dataBuffer += data.toString(); // Append incoming data to the buffer
        let newlineIndex;
        // Process data line by line (assuming C backend sends newline-terminated logs)
        while ((newlineIndex = dataBuffer.indexOf('\n')) !== -1) {
            const logEntry = dataBuffer.substring(0, newlineIndex).trim(); // Extract one complete log entry
            if (logEntry) {
                console.log('Parsed log entry in main process:', logEntry); // MODIFICATION: Added for debugging
                if (mainWindow && !mainWindow.isDestroyed()) {
                    // Send the parsed log entry to the renderer process for display
                    mainWindow.webContents.send('live-log-entry', logEntry);
                }
            }
            dataBuffer = dataBuffer.substring(newlineIndex + 1); // Remove processed log from buffer
        }
    });

    // Event handler for connection errors
    liveLogClient.on('error', (err) => {
        console.error('Error with live log connection to C IDS:', err.message);
        if (mainWindow && !mainWindow.isDestroyed()) {
            // Inform the renderer process about the error
            mainWindow.webContents.send('live-log-status', `ERROR: Live log connection failed. (${err.message})`);
        }
        if (liveLogClient) {
            liveLogClient.destroy(); // Ensure the socket is properly closed on error
            liveLogClient = null; // Mark as null immediately after destruction
        }
        reconnectAttempt++;
        // Attempt to reconnect after a delay
        setTimeout(connectLiveLogClient, RECONNECT_DELAY_MS);
    });

    // Event handler for connection closure
    liveLogClient.on('close', () => {
        console.log('Live log connection to C IDS closed.');
        if (mainWindow && !mainWindow.isDestroyed()) {
            // Inform the renderer process that the stream has stopped
            mainWindow.webContents.send('live-log-status', 'Live log stream stopped.');
        }
        liveLogClient = null; // Mark as null
        // Reconnection logic: if closed unexpectedly, attempt to reconnect
        reconnectAttempt++;
        setTimeout(connectLiveLogClient, RECONNECT_DELAY_MS); // Attempt to reconnect after a delay
    });
}


// IPC handler triggered by the renderer process to start the live log stream
ipcMain.on('start-live-log', (event) => {
    console.log('Received request to start live log stream.');
    reconnectAttempt = 0; // Reset attempts when user explicitly starts
    connectLiveLogClient(event); // Call the function to connect and start streaming
});

// IPC handler triggered by the renderer process to stop the live log stream
ipcMain.on('stop-live-log', (event) => {
    if (liveLogClient) {
        console.log('Stopping live log stream.');
        liveLogClient.write('STOP_LOG_STREAM\n'); // Send stop command to C backend
        liveLogClient.end(); // Gracefully close the client socket
        event.reply('live-log-status', 'Live log stream stopping command sent.');
    } else {
        console.log('No active live log stream to stop.');
        event.reply('live-log-status', 'No active live log stream.');
    }
});

// --- END LIVE LOGGING LOGIC ---


// IPC handler for uploading signatures (existing code)
ipcMain.on('upload-signatures', (event, signaturesJsonString) => {
    const client = new net.Socket();
    client.connect(C_IDS_PORT, C_IDS_HOST, () => {
        console.log('Connected to C IDS backend for signature upload.');
        event.reply('upload-status', 'Uploading signatures...');
        client.write(`UPLOAD_SIGNATURES\n${signaturesJsonString}\n`); // Send the command and JSON
    });

    client.on('data', (data) => {
        const response = data.toString().trim();
        console.log('Response from C IDS (upload):', response);
        event.reply('upload-status', response);
        client.end(); // Close connection after response
    });

    client.on('error', (err) => {
        console.error('Signature upload connection error:', err.message);
        event.reply('upload-status', `ERROR: Signature upload failed. (${err.message})`);
    });
});

// IPC handler for getting IDS status (existing code)
ipcMain.handle('get-ids-status', async () => {
    return new Promise((resolve, reject) => {
        const client = new net.Socket();
        let responseData = '';

        client.connect(C_IDS_PORT, C_IDS_HOST, () => {
            console.log('Connected to C IDS backend for status request.');
            client.write('GET_IDS_STATUS\n'); // Send command
        });

        client.on('data', (data) => {
            responseData += data.toString();
        });

        client.on('end', () => {
            resolve(responseData.trim()); // Resolve with the trimmed response
        });

        client.on('error', (err) => {
            console.error('IDS status connection error:', err.message);
            reject(new Error(`Failed to get IDS status: ${err.message}`));
        });

        client.on('close', () => {
            console.log('Status connection to C IDS closed.');
        });
    });
});