// Define socket and messages_received at global scope
var socket;
var messages_received = [];
var currentPage = 1;

$(document).ready(function () {
    // Firebase configuration can be injected as window.firebaseConfig from template/env.
    const firebaseConfig = window.firebaseConfig || null;
    let db = null;
    let auth = null;

    // Initialize Firebase only when config is available and SDK is loaded.
    if (typeof firebase !== "undefined" && firebaseConfig && firebaseConfig.apiKey) {
        if (!firebase.apps.length) {
            firebase.initializeApp(firebaseConfig);
        }
        db = firebase.firestore();
        auth = firebase.auth();
    } else {
        console.warn("Firebase config missing. Running dashboard without Firestore listeners.");
    }

    // Initialize Socket.IO connection
    socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
    var ctx = document.getElementById("myChart").getContext('2d');
    var itemsPerPage = 10;
    const originalDocumentTitle = document.title;
    let attackAlertCount = 0;
    let lastDesktopNotificationAt = 0;
    let lastSoundAt = 0;
    let lastToastAt = 0;

    // Load saved flows from localStorage
    loadFlowsFromLocal();

  
// Modified auth state handler
if (auth) {
    auth.onAuthStateChanged(user => {
        if (user) {
            // User is signed in
            console.log("User is signed in:", user.uid);

            // Check if this is a new session
            fetch('/check-session')
                .then(response => response.json())
                .then(data => {
                    if (data.new_session) {
                        // Clear any existing flows for this user
                        clearAllFlowStorage();
                    }
                    initializeFirebaseListeners();
                })
                .catch(error => {
                    console.error("Error checking session:", error);
                    initializeFirebaseListeners();
                });
        } else {
            // User signed out - clear flows
            clearAllFlowStorage();
        }
    });
}

    // Function to initialize all Firebase listeners
    function initializeFirebaseListeners() {
        updateNotificationBadge();
        updateHighRiskCounter();
        setupGlobalStatsListener();
    }

    const chartSubtitle = document.getElementById("chart-subtitle");

    function updateChartSubtitle(text) {
        if (chartSubtitle) {
            chartSubtitle.textContent = text;
        }
    }

    function getFlowTimestamp(row) {
        const raw = row && row[6] ? String(row[6]).trim() : "";
        const parsed = raw ? new Date(raw) : new Date();
        return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
    }

    function floorToMinute(dateObj) {
        const d = new Date(dateObj);
        d.setSeconds(0, 0);
        return d;
    }

    function formatMinuteLabel(dateObj) {
        return dateObj.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }

    function buildThreatTimeline(windowMinutes) {
        const now = new Date();
        const points = [];
        const labels = [];
        const attacks = [];
        const benign = [];

        for (let i = windowMinutes - 1; i >= 0; i--) {
            const bucket = new Date(now.getTime() - i * 60000);
            const floored = floorToMinute(bucket);
            const key = floored.getTime();
            points.push(key);
            labels.push(formatMinuteLabel(floored));
            attacks.push(0);
            benign.push(0);
        }

        const indexMap = {};
        for (let i = 0; i < points.length; i++) {
            indexMap[points[i]] = i;
        }

        let totalAttacks = 0;
        let totalBenign = 0;
        for (let i = 0; i < messages_received.length; i++) {
            const row = messages_received[i];
            const ts = floorToMinute(getFlowTimestamp(row)).getTime();
            const idx = indexMap[ts];
            if (idx === undefined) continue;

            const prediction = row && row[row.length - 3] ? String(row[row.length - 3]) : "Unknown";
            const isAttack = prediction.toLowerCase() !== "benign";
            if (isAttack) {
                attacks[idx] += 1;
                totalAttacks += 1;
            } else {
                benign[idx] += 1;
                totalBenign += 1;
            }
        }

        return {
            labels,
            attacks,
            benign,
            totalAttacks,
            totalBenign
        };
    }

    function refreshFlowChart() {
        if (!myChart) return;
        const timeline = buildThreatTimeline(10);
        const totalFlows = timeline.totalAttacks + timeline.totalBenign;
        if (!totalFlows) {
            myChart.data.labels = ["No activity"];
            myChart.data.datasets[0].data = [0];
            myChart.data.datasets[1].data = [0];
            myChart.update();
            updateChartSubtitle("No captured flow activity in the last 10 minutes.");
            return;
        }

        myChart.data.labels = timeline.labels;
        myChart.data.datasets[0].data = timeline.attacks;
        myChart.data.datasets[1].data = timeline.benign;
        myChart.update();

        const attackRate = ((timeline.totalAttacks / totalFlows) * 100).toFixed(1);
        updateChartSubtitle(
            `Last 10 min: ${timeline.totalAttacks} attacks, ${timeline.totalBenign} benign (${attackRate}% attack rate)`
        );
    }

    // Initialize Chart.js
    var myChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ["No activity"],
            datasets: [{
                label: 'Attacks',
                data: [0],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.15)',
                pointBackgroundColor: '#ef4444',
                pointRadius: 3,
                pointHoverRadius: 5,
                borderWidth: 2.5,
                fill: true,
                tension: 0.35
            }, {
                label: 'Benign',
                data: [0],
                borderColor: '#22c55e',
                backgroundColor: 'rgba(34, 197, 94, 0.10)',
                pointBackgroundColor: '#22c55e',
                pointRadius: 3,
                pointHoverRadius: 5,
                borderWidth: 2.5,
                fill: true,
                tension: 0.35
            }]
        },
        options: {
            maintainAspectRatio: false,
            legend: {
                display: true,
                position: 'top'
            },
            animation: {
                duration: 400
            },
            tooltips: {
                mode: 'index',
                intersect: false,
                callbacks: {
                    label: function(tooltipItem) {
                        return ` ${tooltipItem.datasetLabel}: ${tooltipItem.yLabel}`;
                    }
                }
            },
            scales: {
                xAxes: [{
                    gridLines: { display: false },
                    ticks: {
                        autoSkip: false,
                        maxRotation: 35,
                        minRotation: 15,
                        fontColor: "#334155"
                    }
                }],
                yAxes: [{
                    ticks: {
                        beginAtZero: true,
                        precision: 0,
                        fontColor: "#334155"
                    },
                    gridLines: {
                        color: "rgba(148, 163, 184, 0.22)"
                    }
                }]
            }
        }
    });

    // Setup real-time stats listener with enhanced error handling
    function setupGlobalStatsListener() {
        db.collection("global_stats").doc("realtime")
            .onSnapshot((doc) => {
                try {
                    const data = doc.data();
                    if (data) {
                        $("#active-sessions").text(data.active_sessions || 0);
                        $("#current-threats").text(data.threats_last_hour || 0);
                        
                        // Chart is driven by captured flow timeline, not session count snapshot.
                    }
                } catch (error) {
                    console.error("Error processing realtime stats:", error);
                    toastr.error("Unable to get real-time statistics");
                }
            }, (error) => {
                handleFirebaseError(error, "global_stats");
            });
    }

    function plainFlowValue(value) {
        const holder = document.createElement("div");
        holder.innerHTML = String(value ?? "Unknown");
        return (holder.textContent || holder.innerText || "Unknown").trim();
    }

    function escapedFlowValue(value) {
        return $("<div>").text(plainFlowValue(value)).html();
    }

    function updateDesktopNotificationStatus() {
        const $button = $("#enable-desktop-notifications");
        const $status = $("#notification-status");

        if (!("Notification" in window)) {
            $status.text("Not supported by this browser");
            $button.prop("disabled", true).text("Unavailable");
            return;
        }

        if (Notification.permission === "granted") {
            $status.text("Enabled - alerts can appear outside this tab");
            $button.prop("disabled", true).text("Enabled");
        } else if (Notification.permission === "denied") {
            $status.text("Blocked in browser settings");
            $button.prop("disabled", true).text("Blocked");
        } else {
            $status.text("Permission required for desktop popups");
            $button.prop("disabled", false).text("Enable alerts");
        }
    }

    $("#enable-desktop-notifications").on("click", async function() {
        if (!("Notification" in window)) return;

        try {
            const permission = await Notification.requestPermission();
            updateDesktopNotificationStatus();
            if (permission === "granted") {
                toastr.success("Desktop threat alerts are enabled.", "Notifications enabled");
            } else {
                toastr.warning("Desktop alerts were not enabled. Dashboard alerts will still work.");
            }
        } catch (error) {
            console.error("Unable to request desktop notification permission:", error);
            toastr.error("Could not enable desktop notifications.");
        }
    });

    $("#acknowledge-attack").on("click", function() {
        $("#attack-alert").prop("hidden", true).removeClass("is-critical");
        attackAlertCount = 0;
        document.title = originalDocumentTitle;
    });

    $(window).on("focus", function() {
        document.title = originalDocumentTitle;
    });

    function showPersistentAttackAlert(riskLevel, classification, flowData) {
        attackAlertCount += 1;
        const isCritical = riskLevel === "very_high";
        const source = plainFlowValue(flowData[1]);
        const destination = plainFlowValue(flowData[3]);
        const protocol = plainFlowValue(flowData[5]);
        const riskText = riskLevel.replaceAll("_", " ").toUpperCase();

        $("#attack-alert")
            .prop("hidden", false)
            .toggleClass("is-critical", isCritical);
        $("#attack-alert-title").text(isCritical ? "Critical network attack detected" : "Network attack detected");
        $("#attack-alert-detail").text(`${classification} from ${source} to ${destination} over ${protocol} - ${riskText} risk`);
        $("#attack-alert-count").text(`${attackAlertCount} active alert${attackAlertCount === 1 ? "" : "s"}`);
        document.title = `(${attackAlertCount}) ATTACK - ${originalDocumentTitle}`;
    }

    function sendDesktopThreatNotification(riskLevel, classification, flowData) {
        if (!("Notification" in window) || Notification.permission !== "granted") return;

        const now = Date.now();
        const isCritical = riskLevel === "very_high";
        if (!isCritical && now - lastDesktopNotificationAt < 15000) return;
        lastDesktopNotificationAt = now;

        const notification = new Notification(
            isCritical ? "Critical network attack detected" : "Network attack detected",
            {
                body: `${classification}: ${plainFlowValue(flowData[1])} -> ${plainFlowValue(flowData[3])} (${plainFlowValue(flowData[5])})`,
                icon: "/static/images/warning.png",
                tag: "netmask-active-attack",
                renotify: true,
                requireInteraction: isCritical
            }
        );
        notification.onclick = function() {
            window.focus();
            notification.close();
        };
    }

    function playThreatSound() {
        const now = Date.now();
        if (now - lastSoundAt < 5000) return;
        lastSoundAt = now;

        const alertSound = document.getElementById("alert-sound");
        if (!alertSound) return;

        alertSound.pause();
        alertSound.currentTime = 0;
        alertSound.volume = 0.7;
        const playPromise = alertSound.play();
        if (playPromise !== undefined) {
            playPromise.catch(() => {
                $(document).one("click", function() {
                    alertSound.play().catch(error => console.error("Alert sound failed:", error));
                });
            });
        }
    }

    // Notify the user when suspicious or high-risk traffic arrives.
    function checkRiskLevel(riskLevel, flowData) {
        const classification = plainFlowValue(flowData[flowData.length - 3]);
        const isNonBenign = classification.toLowerCase() !== "benign";
        const isHighRisk = riskLevel === "high" || riskLevel === "very_high";

        if (isHighRisk) {
            const highRiskCount = parseInt($("#high-risk-flows").text(), 10) || 0;
            $("#high-risk-flows").text(highRiskCount + 1);
        }

        if (!isHighRisk && !isNonBenign) return;

        showPersistentAttackAlert(riskLevel, classification, flowData);
        sendDesktopThreatNotification(riskLevel, classification, flowData);

        if (isHighRisk) playThreatSound();

        const now = Date.now();
        if (now - lastToastAt >= 3000) {
            lastToastAt = now;
            const isCritical = riskLevel === "very_high";
            const toastrType = isCritical ? "error" : (isHighRisk ? "warning" : "info");
            const alertTitle = isCritical ? "CRITICAL SECURITY ALERT" : "Security Alert";
            const message = `
                <strong>${escapedFlowValue(classification)}</strong> traffic detected!<br>
                <span class="notification-detail">Source: ${escapedFlowValue(flowData[1])}</span><br>
                <span class="notification-detail">Destination: ${escapedFlowValue(flowData[3])}</span><br>
                <span class="notification-detail">Protocol: ${escapedFlowValue(flowData[5])}</span><br>
                <span class="notification-detail">Risk: ${escapedFlowValue(riskLevel.replaceAll("_", " "))}</span>
            `;

            toastr.options = {
                closeButton: true,
                progressBar: true,
                timeOut: isHighRisk ? 10000 : 5000,
                extendedTimeOut: 3000,
                positionClass: "toast-top-right",
                escapeHtml: false
            };
            toastr[toastrType](message, alertTitle);
        }

        if (db && typeof firebase !== "undefined" && firebase.apps.length) {
            db.collection("notifications").add({
                type: isHighRisk ? "high_risk_flow" : "suspicious_flow",
                risk_level: riskLevel,
                classification: classification,
                source_ip: plainFlowValue(flowData[1]),
                dest_ip: plainFlowValue(flowData[3]),
                protocol: plainFlowValue(flowData[5]),
                timestamp: firebase.firestore.FieldValue.serverTimestamp(),
                viewed: false
            }).catch(error => console.error("Error saving notification:", error));
        }
    }

    updateDesktopNotificationStatus();
    function renderIncidents(items, summary) {
        const list = document.getElementById("incident-list");
        const summaryNode = document.getElementById("incident-summary");
        if (!list || !summaryNode) return;
        const openCount = summary && Number(summary.new) ? Number(summary.new) : 0;
        summaryNode.textContent = `${openCount} open`;
        if (!Array.isArray(items) || items.length === 0) {
            list.innerHTML = '<p class="incident-empty">No suspicious incidents detected.</p>';
            return;
        }
        list.innerHTML = items.slice(0, 10).map((incident) => {
            const risk = String(incident.risk_level || "medium").toLowerCase();
            const status = String(incident.status || "new").toLowerCase();
            const route = `${incident.source_ip || "?"} → ${incident.destination_ip || "?"}`;
            const acknowledge = status === "new"
                ? `<button type="button" class="btn btn-default btn-sm acknowledge-incident" data-incident-id="${escapedFlowValue(incident.incident_id)}">Acknowledge</button>`
                : '<span class="incident-meta">Acknowledged</span>';
            return `<article class="incident-item" data-risk="${escapedFlowValue(risk)}" data-status="${escapedFlowValue(status)}">
                <div><div class="incident-id">${escapedFlowValue(incident.incident_id)}</div><div class="incident-meta">${escapedFlowValue(risk.replaceAll("_", " "))}</div></div>
                <div><strong>${escapedFlowValue(incident.classification)}</strong><div class="incident-meta">${escapedFlowValue(route)} · ${escapedFlowValue(incident.protocol)}</div></div>
                <span>${escapedFlowValue(incident.event_count || 1)} event(s)</span>
                ${acknowledge}
            </article>`;
        }).join("");
    }

    function refreshIncidents() {
        fetch('/api/incidents?limit=10', {headers: {'Accept': 'application/json'}})
            .then((response) => response.ok ? response.json() : Promise.reject(new Error(`HTTP ${response.status}`)))
            .then((payload) => renderIncidents(payload.items, payload.summary))
            .catch((error) => console.warn("Incident refresh unavailable:", error));
    }

    $(document).on('click', '.acknowledge-incident', function () {
        const incidentId = $(this).data('incident-id');
        fetch(`/api/incidents/${encodeURIComponent(incidentId)}/acknowledge`, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || ''
            }
        }).then((response) => {
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            refreshIncidents();
        }).catch(() => toastr.error("Could not acknowledge the incident."));
    });

    // Update table with pagination
    function updateTable(page) {
        const start = (page - 1) * itemsPerPage;
        const paginatedData = messages_received.slice(start, start + itemsPerPage);
        let messagesString = `
            <tr>
                <th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th>
                <th>Dst Port</th><th>Protocol</th><th>Flow Start</th><th>Flow End</th>
                <th>App Name</th><th>PID</th><th>Prediction</th><th>Prob</th>
                <th>Risk</th><th>Details</th>
            </tr>`;

        paginatedData.forEach((row) => {
            const riskLevel = String(row[row.length - 1] || "unknown").toLowerCase().replaceAll(" ", "_");
            const rowClass = riskLevel.includes("high") ? "high-risk-row" : "";
            messagesString += `<tr class="${rowClass}" data-risk="${escapedFlowValue(riskLevel)}">`;
            row.forEach((value, index) => {
                if (index === row.length - 1) {
                    messagesString += `<td><span class="risk-badge risk-${escapedFlowValue(riskLevel)}">${escapedFlowValue(value)}</span></td>`;
                } else {
                    messagesString += `<td>${escapedFlowValue(value)}</td>`;
                }
            });
            const flowId = String(row[0]);
            const details = /^\d+$/.test(flowId)
                ? `<a href="/detail?flow_id=${encodeURIComponent(flowId)}" class="btn btn-sm btn-primary">Details</a>`
                : '<span class="incident-meta">Simulation</span>';
            messagesString += `<td>${details}</td></tr>`;
        });
        $('#details').html(messagesString);

        const totalPages = Math.ceil(messages_received.length / itemsPerPage);
        let paginationHtml = '';
        for (let p = 1; p <= totalPages; p++) {
            paginationHtml += `<li class="page-item${p === currentPage ? ' active' : ''}"><a class="page-link" href="#" data-page="${p}">${p}</a></li>`;
        }
        $('#pagination').html(paginationHtml);
        updateFilteredCount();
    }

    refreshIncidents();

    // Update filtered count function
    function updateFilteredCount() {
        const visibleRows = $("#details tr:visible").length - 1; // -1 for header
        $("#filtered-count").text(visibleRows);
    }

    // Handle logout
   // Enhanced logout handler
$(document).on('click', '#logout-button', function(e) {
    e.preventDefault();
    
    // Show loading indicator
    toastr.info("Logging out...", "", {timeOut: 2000});
    
    // Clear local storage first
    if (clearAllFlowStorage()) {
        // Then sign out from Firebase
        if (!auth) {
            window.location.href = '/logout';
            return;
        }
        auth.signOut().then(() => {
            // Optionally call server-side cleanup
            fetch('/clear-local-flows')
                .then(response => response.json())
                .then(data => {
                    console.log("Server cleanup response:", data);
                    // Redirect to logout endpoint
                    window.location.href = '/logout';
                })
                .catch(error => {
                    console.error("Error calling server cleanup:", error);
                    // Still proceed with logout
                    window.location.href = '/logout';
                });
        }).catch(error => {
            console.error("Sign out error:", error);
            toastr.error("Logout failed. Please try again.");
        });
    } else {
        toastr.error("Failed to clear local data. Logout aborted.");
    }
});

    
    // Handle pagination clicks
    $(document).on('click', '.page-link', function (e) {
        e.preventDefault();
        currentPage = $(this).data('page');
        updateTable(currentPage);
    });

    // Setup Socket.IO event handlers
    socket.on('newresult', function (msg) {
        try {
            // Add to messages array with pagination support
            if (messages_received.length >= 100) {
                messages_received.shift();
            }
            messages_received.push(msg.result);
            updateTable(currentPage);
            
            // Save to localStorage for persistence across refreshes
            saveFlowsToLocal();

            // Check risk level and notify
            checkRiskLevel(msg.risk_level, msg.result);
            if (msg.incident) refreshIncidents();

            // Update chart based on all captured rows for stable visualization.
            refreshFlowChart();
            
            // Debug information
            console.log("Received classification:", msg.classification);
            
            // Increment current threats counter (for any non-benign flows)
            if (msg.classification && msg.classification !== "Benign") {
                console.log("Non-benign traffic detected:", msg.classification);
                let currentThreats = parseInt($("#current-threats").text()) || 0;
                $("#current-threats").text(currentThreats + 1);
            }
        } catch (error) {
            console.error("Error processing new result:", error);
        }
    });

    // Handle Socket.IO connection errors
    socket.on('connect_error', function (error) {
        console.error('Socket.IO connection error:', error);
        toastr.error("Connection lost. Attempting to reconnect...");
        setTimeout(function() {
            socket.connect();
        }, 3000);
    });

    // Handle reconnection
    socket.on('reconnect', function() {
        toastr.success("Connection reestablished", "Success");
    });

    // Notification badge update
    function updateNotificationBadge() {
        db.collection("notifications")
            .where("viewed", "==", false)
            .onSnapshot((snapshot) => {
                const count = snapshot.size;
                const badge = $("#notification-badge");
                
                if (count > 0) {
                    badge.text(count).show();
                } else {
                    badge.hide();
                }
            }, (error) => {
                handleFirebaseError(error, "notification_badge");
            });
    }

    // Function to track high-risk flows
    function updateHighRiskCounter() {
        if (firebase.apps.length) {
            db.collection("malicious_flows")
                .where("risk.level", "in", ["high", "very_high"])
                .onSnapshot((snapshot) => {
                    try {
                        $("#high-risk-flows").text(snapshot.size || 0);
                    } catch (error) {
                        console.error("Error updating high risk counter:", error);
                    }
                }, (error) => {
                    handleFirebaseError(error, "high_risk_counter");
                });
        }
    }

    // Improved Risk filter handling
    $("#risk-filter").on("change", function() {
        const selectedRisk = $(this).val().toLowerCase();
        
        // Show all rows first (including header)
        $("#details tr").show();
        
        if (selectedRisk !== "all") {
            // Hide non-matching rows (skip header row)
            $("#details tr:not(:first-child)").each(function() {
                const riskCell = $(this).find("td:nth-child(13)").text().toLowerCase();
                const normalizedRisk = selectedRisk.replace("_", " ");
                
                if (!riskCell.includes(normalizedRisk)) {
                    $(this).hide();
                }
            });
        }
        
        // Update count of visible rows
        updateFilteredCount();
    });

    // Fixed download report function
  $("#download-report").on("click", function() {
    try {
        // Get the currently selected risk filter
        const selectedRisk = $("#risk-filter").val().toLowerCase();
        
        // Collect all data from messages_received (not just visible rows)
        let filteredData = messages_received;
        
        // Filter based on risk level if not "all"
        if (selectedRisk !== "all") {
            const normalizedRisk = selectedRisk.replace("_", " ");
            filteredData = messages_received.filter(row => {
                const riskCell = row[row.length - 1].toLowerCase();
                return riskCell.includes(normalizedRisk);
            });
        }

        if (filteredData.length === 0) {
            toastr.warning("No data to download with current filter");
            return;
        }

        // Get headers
        const headers = [
            'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 
            'Protocol', 'Flow Start', 'Flow End', 'App Name', 'PID',
            'Prediction', 'Prob', 'Risk'
        ];

        // Build CSV content
        const csvRows = [headers.join(",")];
        
        filteredData.forEach(row => {
            const rowData = [];
            // Get all columns except the Details button (first 13 columns)
            for (let j = 0; j < 13; j++) {
                // Clean text content for CSV
                let text = String(row[j]).replace(/<[^>]*>/g, '');
                text = text.replace(/,/g, ' '); // Replace commas with spaces
                text = text.replace(/\n/g, ' '); // Remove newlines
                rowData.push(`"${text}"`); // Wrap in quotes to handle special chars
            }
            csvRows.push(rowData.join(","));
        });

        // Create and download file
        const csvContent = csvRows.join("\n");
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        // Use filter level in filename
        const filename = selectedRisk === "all" ? 
            `netmask-full-report-${timestamp}.csv` :
            `netmask-${selectedRisk}-risk-${timestamp}.csv`;
            
        link.setAttribute("href", url);
        link.setAttribute("download", filename);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        toastr.success(`Downloaded ${filteredData.length} rows`);
    } catch (e) {
        console.error("Error downloading report:", e);
        toastr.error("Failed to download report: " + e.message);
    }
});

    // Notification panel toggler
    $("#notifications-link").on("click", function(e) {
        e.preventDefault();
        // Implementation for notifications panel would go here
        toastr.info("Notifications panel functionality coming soon");
    });
    
    // Initialize filtered count on page load
    setTimeout(updateFilteredCount, 1000);
    setTimeout(refreshFlowChart, 1000);

    // Improve error handling for Firebase operations
    function handleFirebaseError(error, context) {
        console.error(`Firebase error in ${context}:`, error);
        
        // Only show one error notification per type to avoid spamming
        const errorKey = `shown_${context}_error`;
        if (!window[errorKey]) {
            if (error.code === 'permission-denied') {
                toastr.warning("Firebase permission error. Please check authentication.", "Access Denied");
            } else {
                toastr.error("Error connecting to database. Some features may not work.", "Connection Error");
            }
            window[errorKey] = true;
        }
    }
});


function getCurrentUserId() {
    try {
        if (typeof firebase !== "undefined" && firebase.apps && firebase.apps.length) {
            return firebase.auth().currentUser?.uid || 'anonymous';
        }
    } catch (e) {
        console.warn("Unable to read Firebase user id:", e);
    }
    return 'anonymous';
}

// Function to save flow data to localStorage with user scope
function saveFlowsToLocal() {
    try {
        const userId = getCurrentUserId();
        const key = `netmask_flows_${userId}`;
        localStorage.setItem(key, JSON.stringify(messages_received));
        console.log(`Saved ${messages_received.length} flows to local storage for user ${userId}`);
    } catch (e) {
        console.error("Failed to save flows to localStorage:", e);
    }
}

// Add this function to clear all flow-related data
function clearAllFlowStorage() {
    try {
        // Clear all possible flow storage keys
        localStorage.removeItem('netmask_flows');
        
        // Clear user-specific flows if exists
        const userId = getCurrentUserId();
        localStorage.removeItem(`netmask_flows_${userId}`);
        
        // Clear in-memory storage
        messages_received = [];
        
        // Reset the table display
        updateTable(1);
        
        console.log("Cleared all flow data from storage");
        return true;
    } catch (e) {
        console.error("Error clearing flow storage:", e);
        return false;
    }
}


// Function to load flow data from localStorage with user scope
function loadFlowsFromLocal() {
    try {
        const userId = getCurrentUserId();
        const key = `netmask_flows_${userId}`;
        const savedFlows = localStorage.getItem(key);
        
        if (savedFlows) {
            messages_received = JSON.parse(savedFlows);
            console.log(`Loaded ${messages_received.length} flows from local storage for user ${userId}`);
            if (typeof updateTable === 'function') {
                updateTable(currentPage);
            }
        }
    } catch (e) {
        console.error("Failed to load flows from localStorage:", e);
    }
}

// Add this new function to clear flows for the current user
function clearUserFlows() {
    try {
        const userId = getCurrentUserId();
        const key = `netmask_flows_${userId}`;
        localStorage.removeItem(key);
        console.log(`Cleared flows for user ${userId}`);
        messages_received = []; // Clear in-memory storage too
    } catch (e) {
        console.error("Failed to clear user flows:", e);
    }
}
