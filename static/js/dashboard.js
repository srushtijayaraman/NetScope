/**
 * NetScope 2.0 Dashboard Controller
 * Asynchronous state orchestration, safe DOM rendering, Light/Dark theme switching,
 * flow filtering, alert packet linking, heuristic threshold management, and real-time backend synchronization.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Global State
    const state = {
        currentPage: 1,
        pageSize: 50,
        sortBy: "packet_id",
        sortOrder: "asc",
        flowLimit: 10,
        filters: {
            search: "",
            protocol: "",
            pkt_id: "",
            src_ip: "",
            dst_ip: "",
            src_port: "",
            dst_port: "",
            flow_id: "",
        },
        talkerTab: "sources",
        protocolLayer: "transport",
        timelineMetric: "pps",
        livePollInterval: null,
        isCapturing: false,
    };

    // DOM Elements
    const elements = {
        // Badges & Status
        statusDot: document.getElementById("status-dot"),
        statusText: document.getElementById("status-text"),
        modeBadge: document.getElementById("mode-badge"),
        sessionBadge: document.getElementById("session-badge"),
        banner: document.getElementById("notification-banner"),
        loadingOverlay: document.getElementById("loading-overlay"),
        loadingText: document.getElementById("loading-overlay-text"),
        
        // Summary values
        totalPackets: document.getElementById("val-total-packets"),
        processingPps: document.getElementById("val-processing-pps"),
        totalBytes: document.getElementById("val-total-bytes"),
        avgPacketSize: document.getElementById("val-avg-packet-size"),
        capturePps: document.getElementById("val-capture-pps"),
        captureDuration: document.getElementById("val-capture-duration"),
        throughput: document.getElementById("val-throughput"),
        throughputMbps: document.getElementById("val-throughput-mbps"),
        uniqueHosts: document.getElementById("val-unique-hosts"),
        activeFlows: document.getElementById("val-active-flows"),
        errorsDrops: document.getElementById("val-errors-drops"),

        // Controls
        pcapInput: document.getElementById("pcap-file-input"),
        btnLoadSample: document.getElementById("btn-load-sample"),
        btnOpenConfig: document.getElementById("btn-open-config"),
        btnQuickConfig: document.getElementById("btn-quick-config"),
        interfaceSelect: document.getElementById("interface-select"),
        btnStartLive: document.getElementById("btn-start-live"),
        btnStopLive: document.getElementById("btn-stop-live"),
        btnRefresh: document.getElementById("btn-refresh"),
        btnThemeToggle: document.getElementById("btn-theme-toggle"),
        themeToggleIcon: document.getElementById("theme-toggle-icon"),
        themeToggleLabel: document.getElementById("theme-toggle-label"),
        protocolLayerSelect: document.getElementById("protocol-layer-select"),
        btnToggleTimeline: document.getElementById("btn-toggle-timeline-unit"),

        // Tables & Lists
        topTalkersThead: document.getElementById("top-talkers-thead"),
        topTalkersTbody: document.getElementById("top-talkers-tbody"),
        flowsTbody: document.getElementById("flows-tbody"),
        flowCountBadge: document.getElementById("flow-count-badge"),
        flowLimitSelect: document.getElementById("flow-limit-select"),
        alertsContainer: document.getElementById("alerts-container"),
        alertCountBadge: document.getElementById("alert-count-badge"),

        // Explorer
        filterSearch: document.getElementById("filter-search"),
        filterProtocol: document.getElementById("filter-protocol"),
        filterPktId: document.getElementById("filter-pkt-id"),
        filterSrcIp: document.getElementById("filter-src-ip"),
        filterDstIp: document.getElementById("filter-dst-ip"),
        filterSrcPort: document.getElementById("filter-src-port"),
        filterDstPort: document.getElementById("filter-dst-port"),
        activeFlowBadge: document.getElementById("active-flow-badge"),
        activeFlowId: document.getElementById("active-flow-id"),
        btnResetFilters: document.getElementById("btn-reset-filters"),
        btnExportCsv: document.getElementById("btn-export-csv"),
        packetTableBody: document.getElementById("packet-table-body"),
        packetFilterCount: document.getElementById("packet-filter-count"),
        paginationInfo: document.getElementById("pagination-info"),
        btnPrevPage: document.getElementById("btn-prev-page"),
        btnNextPage: document.getElementById("btn-next-page"),
        pageDisplay: document.getElementById("page-display"),
        pageSizeSelect: document.getElementById("page-size-select"),

        // Packet Modal
        modal: document.getElementById("packet-detail-modal"),
        modalTitle: document.getElementById("modal-packet-title"),
        modalBody: document.getElementById("modal-packet-body"),
        btnCloseModal: document.getElementById("btn-close-modal"),

        // Threshold Config Modal
        configModal: document.getElementById("config-modal"),
        configErrorMsg: document.getElementById("config-error-msg"),
        btnCloseConfig: document.getElementById("btn-close-config"),
        btnCancelConfig: document.getElementById("btn-cancel-config"),
        btnSaveConfig: document.getElementById("btn-save-config"),
        cfgSynFlood: document.getElementById("cfg-syn-flood"),
        cfgPortScan: document.getElementById("cfg-port-scan"),
        cfgPacketRate: document.getElementById("cfg-packet-rate"),
        cfgByteRate: document.getElementById("cfg-byte-rate"),
        cfgHostRatio: document.getElementById("cfg-host-ratio"),
        cfgCooldown: document.getElementById("cfg-cooldown"),

        // NetScope 3.0: Compare & Report Elements
        btnOpenCompare: document.getElementById("btn-open-compare"),
        btnDownloadReport: document.getElementById("btn-download-report"),

        // TCP Conversation Modal
        modalFlowTimeline: document.getElementById("modal-tcp-conversation"),
        btnCloseFlowTimeline: document.getElementById("btn-close-flow-timeline"),
        flowTimelineTbody: document.getElementById("flow-timeline-tbody"),
        modalFlowTitle: document.getElementById("modal-flow-title"),
        modalFlowSubtitle: document.getElementById("modal-flow-subtitle"),
        flowChipHandshake: document.getElementById("flow-chip-handshake"),
        flowChipState: document.getElementById("flow-chip-state"),
        flowChipRetrans: document.getElementById("flow-chip-retrans"),
        flowChipVolume: document.getElementById("flow-chip-volume"),
        flowChipDuration: document.getElementById("flow-chip-duration"),
        btnFlowFilterExplorer: document.getElementById("btn-flow-filter-explorer"),

        // Compare Modal
        modalCompare: document.getElementById("modal-compare"),
        btnCloseCompare: document.getElementById("btn-close-compare"),
        btnCompareWithSample: document.getElementById("btn-compare-with-sample"),
        compareFileInput: document.getElementById("compare-file-input"),
        compareWarningBanner: document.getElementById("compare-warning-banner"),
        compareResults: document.getElementById("compare-results"),
        comparePlaceholder: document.getElementById("compare-placeholder"),
        cmpNameA: document.getElementById("cmp-name-a"),
        cmpNameB: document.getElementById("cmp-name-b"),
        compareMetricsTbody: document.getElementById("compare-metrics-tbody"),
        compareProtocolsTbody: document.getElementById("compare-protocols-tbody"),
    };

    // Helper: Format Bytes
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    // Helper: Show Toast Notification
    function showNotification(message, type = "info", duration = 4000) {
        if (!elements.banner) return;
        elements.banner.className = `notification-banner ${type}`;
        elements.banner.textContent = message;
        elements.banner.style.display = "flex";
        if (duration > 0) {
            setTimeout(() => {
                elements.banner.style.display = "none";
            }, duration);
        }
    }

    // Helper: Loading Spinner
    function showLoading(msg = "Processing capture...") {
        if (elements.loadingText) elements.loadingText.textContent = msg;
        if (elements.loadingOverlay) elements.loadingOverlay.style.display = "flex";
    }
    function hideLoading() {
        if (elements.loadingOverlay) elements.loadingOverlay.style.display = "none";
    }

    // ==========================================================================
    // Theme Management (Light / Dark)
    // ==========================================================================
    const ICONS = {
        sun: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
        moon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
    };

    function initTheme() {
        let current = document.documentElement.getAttribute("data-theme");
        if (!current) {
            try {
                current = localStorage.getItem("netscope_theme");
            } catch (e) {
                current = null;
            }
            if (!current) {
                current = (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
            }
            document.documentElement.setAttribute("data-theme", current);
        }
        updateThemeUI(current);
        NetScopeCharts.setTheme(current);
    }

    function updateThemeUI(theme) {
        if (!elements.btnThemeToggle) return;
        if (theme === "light") {
            elements.themeToggleIcon.innerHTML = ICONS.moon;
            elements.themeToggleLabel.textContent = "Dark";
            elements.btnThemeToggle.title = "Switch to Dark Theme";
        } else {
            elements.themeToggleIcon.innerHTML = ICONS.sun;
            elements.themeToggleLabel.textContent = "Light";
            elements.btnThemeToggle.title = "Switch to Light Theme";
        }
    }

    function toggleTheme() {
        const current = document.documentElement.getAttribute("data-theme") || "dark";
        const next = (current === "dark") ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        try {
            localStorage.setItem("netscope_theme", next);
        } catch (e) {
            console.warn("localStorage unavailable for theme preference:", e);
        }
        updateThemeUI(next);
        NetScopeCharts.setTheme(next);
    }

    if (elements.btnThemeToggle) {
        elements.btnThemeToggle.addEventListener("click", toggleTheme);
    }

    // ==========================================================================
    // Core Data Fetchers
    // ==========================================================================

    // 1. Fetch Interface & Environment Diagnostics
    async function refreshInterfaces() {
        try {
            const res = await fetch("/api/interfaces");
            const data = await res.json();
            elements.interfaceSelect.innerHTML = '<option value="">Select Interface...</option>';

            if (data.interfaces && data.interfaces.length > 0) {
                data.interfaces.forEach(iface => {
                    const opt = document.createElement("option");
                    opt.value = iface.name;
                    opt.textContent = `${iface.name} (${iface.description || iface.ip || 'Ready'})`;
                    elements.interfaceSelect.appendChild(opt);
                });
            } else {
                const opt = document.createElement("option");
                opt.value = "";
                opt.textContent = data.message || "No interfaces detected";
                opt.disabled = true;
                elements.interfaceSelect.appendChild(opt);
            }

            if (!data.supported) {
                elements.btnStartLive.title = data.message;
            }
        } catch (err) {
            console.error("Interface enumeration error:", err);
        }
    }

    // 2. Fetch High-Level Summary Stats
    async function refreshStats() {
        try {
            const res = await fetch("/api/stats");
            const data = await res.json();

            elements.totalPackets.textContent = (data.total_packets || 0).toLocaleString();
            elements.processingPps.textContent = `Processing: ${(data.processing_pps || 0).toFixed(1)} pps`;
            elements.totalBytes.textContent = formatBytes(data.total_bytes || 0);
            elements.avgPacketSize.textContent = `Avg Size: ${(data.average_packet_size_bytes || 0).toFixed(1)} B`;
            elements.capturePps.innerHTML = `${(data.capture_pps || 0).toFixed(2)} <span class="unit">pps</span>`;
            elements.captureDuration.textContent = `Span: ${(data.capture_duration_seconds || 0).toFixed(2)}s`;
            elements.throughput.innerHTML = `${(data.throughput_kbps || 0).toFixed(2)} <span class="unit">kbps</span>`;
            elements.throughputMbps.textContent = `${(data.throughput_mbps || 0).toFixed(4)} Mbps`;
            elements.uniqueHosts.textContent = (data.unique_hosts || 0).toLocaleString();
            elements.activeFlows.textContent = `${(data.active_flows || 0).toLocaleString()} Total Active Flows`;
            elements.errorsDrops.textContent = `${data.parsing_errors || 0} / ${data.queue_drops || 0}`;
        } catch (err) {
            console.error("Stats refresh error:", err);
        }
    }

    // 3. Fetch Protocols
    async function refreshProtocols() {
        try {
            const res = await fetch("/api/protocols");
            const data = await res.json();
            NetScopeCharts.renderProtocolChart(data, state.protocolLayer);
        } catch (err) {
            console.error("Protocol refresh error:", err);
        }
    }

    // 4. Fetch Traffic Timeline
    async function refreshTimeline() {
        try {
            const res = await fetch("/api/traffic-timeline");
            const data = await res.json();
            NetScopeCharts.renderTimelineChart(data.timeline, state.timelineMetric);
        } catch (err) {
            console.error("Timeline refresh error:", err);
        }
    }

    // 5. Fetch Top Talkers & Canonical Flows
    async function refreshTalkersAndFlows() {
        try {
            // A. Fetch Talkers
            const resTalkers = await fetch("/api/top-talkers?limit=8");
            const dataTalkers = await resTalkers.json();
            const talkers = dataTalkers.talkers || {};
            elements.topTalkersTbody.innerHTML = "";

            if (state.talkerTab === "sources" || state.talkerTab === "destinations") {
                elements.topTalkersThead.innerHTML = "<th>IP Address</th><th>Packets</th><th>Volume</th>";
                const list = (state.talkerTab === "sources" ? talkers.sources : talkers.destinations) || [];
                if (list.length === 0) {
                    elements.topTalkersTbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No talker data recorded.</td></tr>';
                } else {
                    list.forEach(item => {
                        const tr = document.createElement("tr");
                        tr.innerHTML = `
                            <td class="mono"><a href="javascript:void(0)" class="filter-link" data-ip="${item.ip}">${item.ip}</a></td>
                            <td class="mono">${item.packets.toLocaleString()}</td>
                            <td class="mono">${formatBytes(item.bytes)}</td>
                        `;
                        elements.topTalkersTbody.appendChild(tr);
                    });
                }
            } else if (state.talkerTab === "ports") {
                elements.topTalkersThead.innerHTML = "<th>Port</th><th>Packets</th><th>Share</th>";
                const ports = dataTalkers.top_ports || [];
                if (ports.length === 0) {
                    elements.topTalkersTbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No port data recorded.</td></tr>';
                } else {
                    ports.forEach(p => {
                        const tr = document.createElement("tr");
                        tr.innerHTML = `
                            <td class="mono"><a href="javascript:void(0)" class="filter-port-link" data-port="${p.port}">${p.port}</a></td>
                            <td class="mono">${p.packets.toLocaleString()}</td>
                            <td class="mono">${p.percentage.toFixed(1)}%</td>
                        `;
                        elements.topTalkersTbody.appendChild(tr);
                    });
                }
            }

            // Click-to-filter on talker IPs and ports
            elements.topTalkersTbody.querySelectorAll(".filter-link").forEach(a => {
                a.addEventListener("click", (e) => {
                    const ip = e.target.dataset.ip;
                    if (state.talkerTab === "sources") {
                        elements.filterSrcIp.value = ip;
                        state.filters.src_ip = ip;
                    } else {
                        elements.filterDstIp.value = ip;
                        state.filters.dst_ip = ip;
                    }
                    state.currentPage = 1;
                    refreshPackets();
                    document.querySelector(".packet-explorer-card").scrollIntoView({ behavior: "smooth" });
                });
            });

            elements.topTalkersTbody.querySelectorAll(".filter-port-link").forEach(a => {
                a.addEventListener("click", (e) => {
                    const port = e.target.dataset.port;
                    elements.filterDstPort.value = port;
                    state.filters.dst_port = port;
                    state.currentPage = 1;
                    refreshPackets();
                    document.querySelector(".packet-explorer-card").scrollIntoView({ behavior: "smooth" });
                });
            });

            // B. Fetch Canonical Flows
            const limit = state.flowLimit || 10;
            const resFlows = await fetch(`/api/flows?limit=${limit}`);
            const dataFlows = await resFlows.json();
            const flows = dataFlows.flows || [];
            const totalFlows = dataFlows.total_flows || flows.length;

            elements.flowCountBadge.textContent = `Showing Top ${flows.length} of ${totalFlows} Flows`;
            elements.flowsTbody.innerHTML = "";

            if (flows.length === 0) {
                elements.flowsTbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No conversation flows recorded.</td></tr>';
            } else {
                flows.forEach(f => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td class="mono"><strong>${f.flow_id}</strong></td>
                        <td class="mono" style="font-size:11.5px;">${f.endpoint_a} &harr; ${f.endpoint_b}</td>
                        <td><span class="badge badge-proto badge-proto-tcp">${f.transport_protocol}</span></td>
                        <td class="mono">${(f.duration || 0).toFixed(2)}s</td>
                        <td class="mono">${f.total_packets}</td>
                        <td class="mono">${formatBytes(f.total_bytes)}</td>
                        <td>
                            <span class="badge">${f.tcp_state || 'STATELESS'}</span>
                            ${f.retransmissions ? `<span class="badge-retrans" title="${f.retransmissions} retransmission(s)">${f.retransmissions} Retrans</span>` : ''}
                        </td>
                        <td>
                            <div style="display:inline-flex; gap:4px;">
                                <button class="btn btn-primary btn-xs btn-inspect-flow" data-flow-id="${f.flow_id}" title="Inspect TCP Handshake & Conversation Progression">Inspect</button>
                                <button class="btn btn-outline btn-xs btn-filter-flow" data-flow-id="${f.flow_id}" title="Filter Explorer to this Flow">Filter</button>
                            </div>
                        </td>
                    `;
                    elements.flowsTbody.appendChild(tr);
                });

                // Attach flow inspect clicks
                elements.flowsTbody.querySelectorAll(".btn-inspect-flow").forEach(btn => {
                    btn.addEventListener("click", (e) => {
                        const flowId = e.target.dataset.flowId;
                        openFlowTimeline(flowId);
                    });
                });

                // Attach flow filter clicks
                elements.flowsTbody.querySelectorAll(".btn-filter-flow").forEach(btn => {
                    btn.addEventListener("click", (e) => {
                        const flowId = e.target.dataset.flowId;
                        applyFlowFilter(flowId);
                    });
                });
            }
        } catch (err) {
            console.error("Talkers/Flows refresh error:", err);
        }
    }

    function applyFlowFilter(flowId) {
        state.filters.flow_id = flowId;
        elements.activeFlowId.textContent = flowId;
        elements.activeFlowBadge.style.display = "inline-flex";
        state.currentPage = 1;
        refreshPackets();
        document.querySelector(".packet-explorer-card").scrollIntoView({ behavior: "smooth" });
        showNotification(`Filtered packet explorer to Conversation Flow: ${flowId}`, "info", 2500);
    }

    function clearFlowFilter() {
        state.filters.flow_id = "";
        elements.activeFlowBadge.style.display = "none";
        state.currentPage = 1;
        refreshPackets();
    }

    elements.activeFlowBadge.addEventListener("click", clearFlowFilter);

    if (elements.flowLimitSelect) {
        elements.flowLimitSelect.addEventListener("change", (e) => {
            state.flowLimit = parseInt(e.target.value) || 10;
            refreshTalkersAndFlows();
        });
    }

    // 6. Fetch Security Alerts (CRITICAL BUG FIX: Guaranteed Non-Undefined Fields)
    async function refreshAlerts() {
        try {
            const res = await fetch("/api/alerts");
            const data = await res.json();
            const alerts = data.alerts || [];

            elements.alertCountBadge.textContent = `${alerts.length} Alerts`;
            elements.alertsContainer.innerHTML = "";

            if (alerts.length === 0) {
                elements.alertsContainer.innerHTML = '<div class="empty-state">No anomalies or heuristic threshold violations detected.</div>';
                return;
            }

            alerts.forEach(alt => {
                const item = document.createElement("div");
                item.className = `alert-item severity-${alt.severity || 'LOW'}`;

                const natureBadge = alt.classification_nature ? 
                    `<span class="badge badge-classification">${alt.classification_nature}</span>` : '';

                // Supporting Packet References
                let pktRefsHtml = '';
                const refs = alt.packet_references || [];
                if (refs.length > 0) {
                    const badges = refs.slice(0, 10).map(id => 
                        `<a href="javascript:void(0)" class="ref-badge alert-pkt-link" data-pkt-id="${id}">#${id}</a>`
                    ).join(" ");
                    const moreCount = refs.length > 10 ? ` <span class="text-muted" style="font-size:10px;">(+${refs.length - 10} more)</span>` : '';
                    pktRefsHtml = `
                        <div class="alert-references">
                            <span class="ref-label">Supporting Packets:</span>
                            <div class="ref-badges">${badges}${moreCount}</div>
                            <a href="javascript:void(0)" class="filter-host-link" data-host="${alt.host}">Filter Host &rarr;</a>
                        </div>
                    `;
                }

                // Defensive Field Resolution (NEVER displays 'undefined' or 'null')
                const observedValue = (alt.observed_value !== undefined && alt.observed_value !== null && alt.observed_value !== "") ? 
                    alt.observed_value : 
                    (alt.observed_metric || (alt.evidence && alt.evidence.syn_count ? `${alt.evidence.syn_count} SYNs` : null) || (alt.evidence && alt.evidence.unique_ports_count ? `${alt.evidence.unique_ports_count} ports probed` : null) || 'Not applicable');

                const thresholdValue = (alt.threshold !== undefined && alt.threshold !== null && alt.threshold !== "") ? 
                    alt.threshold : 
                    (alt.configured_threshold || 'Configured baseline');

                const timeWindow = alt.time_window || 'Sliding window';
                const targetText = alt.target ? `<div class="meta-row"><span class="meta-key">Target:</span> <span class="meta-val mono">${alt.target}</span></div>` : '';

                item.innerHTML = `
                    <div class="alert-content">
                        <div class="alert-header-row">
                            <span class="badge ${alt.severity === 'HIGH' ? 'badge-danger' : (alt.severity === 'MEDIUM' ? 'badge-warning' : 'badge-academic')}">${alt.severity || 'INFO'}</span>
                            <span class="alert-title">${alt.alert_type}</span>
                            ${natureBadge}
                        </div>
                        <div class="alert-desc">${alt.explanation || 'Anomaly heuristic condition matched.'}</div>
                        ${pktRefsHtml}
                    </div>
                    <div class="alert-metadata">
                        <div class="meta-row"><span class="meta-key">Host:</span> <span class="meta-val mono">${alt.host || 'Segment'}</span></div>
                        ${targetText}
                        <div class="meta-row"><span class="meta-key">Observed:</span> <span class="meta-val mono">${observedValue}</span></div>
                        <div class="meta-row"><span class="meta-key">Threshold:</span> <span class="meta-val mono">${thresholdValue}</span></div>
                        <div class="meta-row"><span class="meta-key">Window:</span> <span class="meta-val mono">${timeWindow}</span></div>
                    </div>
                `;
                elements.alertsContainer.appendChild(item);
            });

            // Bind click on individual packet reference badges
            elements.alertsContainer.querySelectorAll(".alert-pkt-link").forEach(a => {
                a.addEventListener("click", (e) => {
                    const pktId = parseInt(e.target.dataset.pktId);
                    if (pktId) showPacketModal(pktId);
                });
            });

            // Bind click on filter host link
            elements.alertsContainer.querySelectorAll(".filter-host-link").forEach(a => {
                a.addEventListener("click", (e) => {
                    const host = e.target.dataset.host;
                    if (host && host !== "Monitored Segment" && host !== "Monitored Link") {
                        elements.filterSrcIp.value = host;
                        state.filters.src_ip = host;
                        state.currentPage = 1;
                        refreshPackets();
                        document.querySelector(".packet-explorer-card").scrollIntoView({ behavior: "smooth" });
                    }
                });
            });
        } catch (err) {
            console.error("Alerts refresh error:", err);
        }
    }

    // 7. Fetch & Render Packet Explorer Table
    async function refreshPackets() {
        const params = new URLSearchParams({
            page: state.currentPage,
            limit: state.pageSize,
            sort_by: state.sortBy,
            sort_order: state.sortOrder,
        });

        if (state.filters.search) params.append("search", state.filters.search);
        if (state.filters.protocol) params.append("protocol", state.filters.protocol);
        if (state.filters.pkt_id) params.append("packet_id", state.filters.pkt_id);
        if (state.filters.src_ip) params.append("src_ip", state.filters.src_ip);
        if (state.filters.dst_ip) params.append("dst_ip", state.filters.dst_ip);
        if (state.filters.src_port) params.append("src_port", state.filters.src_port);
        if (state.filters.dst_port) params.append("dst_port", state.filters.dst_port);
        if (state.filters.flow_id) params.append("flow_id", state.filters.flow_id);

        try {
            const res = await fetch(`/api/packets?${params.toString()}`);
            const data = await res.json();

            const packets = data.packets || [];
            elements.packetFilterCount.textContent = `Showing ${packets.length} of ${data.total.toLocaleString()} packets`;
            elements.paginationInfo.textContent = `Page ${data.page} of ${data.pages} (${data.total.toLocaleString()} total packets)`;
            elements.pageDisplay.textContent = data.page;

            elements.btnPrevPage.disabled = (data.page <= 1);
            elements.btnNextPage.disabled = (data.page >= data.pages);

            elements.packetTableBody.innerHTML = "";
            if (packets.length === 0) {
                elements.packetTableBody.innerHTML = '<tr><td colspan="12" class="text-center text-muted">No packets matching the current filters.</td></tr>';
                return;
            }

            packets.forEach(p => {
                const tr = document.createElement("tr");
                tr.dataset.packetId = p.packet_id;

                const transProto = p.transport_protocol || "-";
                const appProto = p.application_protocol || "-";
                const netProto = p.network_protocol || "-";
                const flags = (p.tcp_flags && p.tcp_flags.length > 0) ? p.tcp_flags.join(",") : "-";

                let protoBadgeClass = "badge-proto";
                if (transProto === "TCP") protoBadgeClass += " badge-proto-tcp";
                else if (transProto === "UDP") protoBadgeClass += " badge-proto-udp";
                else if (transProto === "ICMP") protoBadgeClass += " badge-proto-icmp";
                else if (netProto === "ARP") protoBadgeClass += " badge-proto-arp";

                const flowBadge = p.flow_id ? 
                    `<span class="badge" style="font-size:10px;">${p.flow_id}</span>` : '-';

                const timeStr = p.timestamp_iso ? p.timestamp_iso.substr(11, 12) : "-";
                const relTime = (p.relative_time_sec !== undefined) ? `${p.relative_time_sec.toFixed(3)}s` : "-";

                const srcEndpoint = p.source_port ? `${p.source_ip}:${p.source_port}` : (p.source_ip || "-");
                const dstEndpoint = p.destination_port ? `${p.destination_ip}:${p.destination_port}` : (p.destination_ip || "-");

                tr.innerHTML = `
                    <td class="mono font-semibold">${p.packet_id}</td>
                    <td>${flowBadge}</td>
                    <td class="mono text-muted">${timeStr}</td>
                    <td class="mono text-muted">${relTime}</td>
                    <td class="mono">${srcEndpoint}</td>
                    <td class="mono">${dstEndpoint}</td>
                    <td><span class="badge">${netProto}</span></td>
                    <td><span class="badge ${protoBadgeClass}">${transProto}</span></td>
                    <td><span class="badge" style="font-size:10px;">${appProto}</span></td>
                    <td class="mono">${p.packet_length} B</td>
                    <td class="mono" style="font-size:10px;">${flags}</td>
                    <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis;" title="${p.summary || ''}">${p.summary || '-'}</td>
                `;
                elements.packetTableBody.appendChild(tr);
            });

            // Bind click to open detail modal
            elements.packetTableBody.querySelectorAll("tr").forEach(tr => {
                tr.addEventListener("click", () => {
                    const pktId = tr.dataset.packetId;
                    if (pktId) showPacketModal(pktId);
                });
            });
        } catch (err) {
            console.error("Packet table query error:", err);
        }
    }

    // 8. Single Packet Inspector Modal
    async function showPacketModal(packetId) {
        try {
            const res = await fetch(`/api/packets/${packetId}`);
            if (!res.ok) {
                showNotification(`Packet #${packetId} not found.`, "error");
                return;
            }
            const p = await res.json();
            elements.modalTitle.textContent = `Packet #${p.packet_id} Protocol Layer Inspector`;

            const d = p.details || {};
            const link = d.link_layer || {};
            const net = d.network_layer || {};
            const trans = d.transport_layer || {};
            const app = d.application_layer || {};

            let html = `
                <!-- General Metadata -->
                <div class="layer-card">
                    <div class="layer-card-title">Frame Overview</div>
                    <div class="layer-card-content">
                        <div class="field-row"><span class="field-key">Frame Number:</span><span class="field-val">#${p.packet_id}</span></div>
                        <div class="field-row"><span class="field-key">Conversation Flow:</span><span class="field-val">${p.flow_id || 'None'}</span></div>
                        <div class="field-row"><span class="field-key">Captured Length:</span><span class="field-val">${p.captured_length || p.packet_length} Bytes</span></div>
                        <div class="field-row"><span class="field-key">Wire Length:</span><span class="field-val">${p.packet_length} Bytes</span></div>
                        <div class="field-row"><span class="field-key">Epoch Timestamp:</span><span class="field-val">${p.timestamp}</span></div>
                        <div class="field-row"><span class="field-key">Relative Offset:</span><span class="field-val">+${(p.relative_time_sec || 0).toFixed(4)}s</span></div>
                        <div class="field-row"><span class="field-key">UTC Arrival:</span><span class="field-val">${p.timestamp_iso}</span></div>
                        <div class="field-row"><span class="field-key">Parsing Status:</span><span class="field-val">${p.parsing_status}</span></div>
                    </div>
                </div>

                <!-- Link Layer (Layer 2) -->
                <div class="layer-card">
                    <div class="layer-card-title">Link Layer (Layer 2 - ${link.type || 'Ethernet'})</div>
                    <div class="layer-card-content">
                        <div class="field-row"><span class="field-key">Source MAC:</span><span class="field-val">${link.source_mac || p.source_mac || 'N/A'}</span></div>
                        <div class="field-row"><span class="field-key">Destination MAC:</span><span class="field-val">${link.destination_mac || p.destination_mac || 'N/A'}</span></div>
                        <div class="field-row"><span class="field-key">EtherType:</span><span class="field-val">${link.ether_type || 'N/A'}</span></div>
                    </div>
                </div>

                <!-- Network Layer (Layer 3) -->
                <div class="layer-card">
                    <div class="layer-card-title">Network Layer (Layer 3 - ${net.protocol || p.network_protocol})</div>
                    <div class="layer-card-content">
                        <div class="field-row"><span class="field-key">Source Address:</span><span class="field-val">${p.source_ip || 'N/A'}</span></div>
                        <div class="field-row"><span class="field-key">Destination Address:</span><span class="field-val">${p.destination_ip || 'N/A'}</span></div>
                        ${net.ttl !== undefined ? `<div class="field-row"><span class="field-key">Time to Live (TTL):</span><span class="field-val">${net.ttl}</span></div>` : ''}
                        ${net.identification !== undefined ? `<div class="field-row"><span class="field-key">Identification:</span><span class="field-val">${net.identification}</span></div>` : ''}
                        ${net.checksum ? `<div class="field-row"><span class="field-key">Checksum:</span><span class="field-val">${net.checksum}</span></div>` : ''}
                        ${net.flags !== undefined ? `<div class="field-row"><span class="field-key">IP Flags:</span><span class="field-val">${net.flags || 'None'}</span></div>` : ''}
                        ${net.fragment_offset !== undefined ? `<div class="field-row"><span class="field-key">Fragment Offset:</span><span class="field-val">${net.fragment_offset}</span></div>` : ''}
                    </div>
                </div>

                <!-- Transport Layer (Layer 4) -->
                <div class="layer-card">
                    <div class="layer-card-title">Transport Layer (Layer 4 - ${trans.protocol || p.transport_protocol})</div>
                    <div class="layer-card-content">
                        ${p.source_port ? `<div class="field-row"><span class="field-key">Source Port:</span><span class="field-val">${p.source_port}</span></div>` : ''}
                        ${p.destination_port ? `<div class="field-row"><span class="field-key">Destination Port:</span><span class="field-val">${p.destination_port}</span></div>` : ''}
                        ${trans.sequence_number !== undefined ? `<div class="field-row"><span class="field-key">Sequence Number:</span><span class="field-val">${trans.sequence_number}</span></div>` : ''}
                        ${trans.acknowledgment_number !== undefined ? `<div class="field-row"><span class="field-key">Acknowledgment Number:</span><span class="field-val">${trans.acknowledgment_number}</span></div>` : ''}
                        ${p.tcp_flags ? `<div class="field-row"><span class="field-key">TCP Flags:</span><span class="field-val">${p.tcp_flags.join(", ") || 'NONE'} (${p.tcp_flags_hex || ''})</span></div>` : ''}
                        ${trans.window_size !== undefined ? `<div class="field-row"><span class="field-key">Window Size:</span><span class="field-val">${trans.window_size}</span></div>` : ''}
                        ${trans.checksum ? `<div class="field-row"><span class="field-key">Checksum:</span><span class="field-val">${trans.checksum}</span></div>` : ''}
                        ${trans.type_name ? `<div class="field-row"><span class="field-key">ICMP Type:</span><span class="field-val">${trans.type_name} (${trans.type})</span></div>` : ''}
                        ${trans.code !== undefined ? `<div class="field-row"><span class="field-key">ICMP Code:</span><span class="field-val">${trans.code}</span></div>` : ''}
                    </div>
                </div>
            `;

            // Application Layer (Layer 7)
            if (p.application_protocol && p.application_protocol !== "None") {
                let appFields = '';
                if (app.protocol === "DNS") {
                    const ansList = (app.answers && app.answers.length > 0) ? app.answers.join("<br>") : "None (Query / No Answer)";
                    const flagsList = (app.dns_flags && app.dns_flags.length > 0) ? app.dns_flags.join(", ") : "Standard";
                    appFields = `
                        <div class="field-row"><span class="field-key">Transaction ID:</span><span class="field-val">${app.transaction_id || '0x0'}</span></div>
                        <div class="field-row"><span class="field-key">Message Type:</span><span class="field-val">${app.message_type || (app.is_response ? 'Response' : 'Query')}</span></div>
                        <div class="field-row"><span class="field-key">Query Domain:</span><span class="field-val">${app.query_name || 'N/A'}</span></div>
                        <div class="field-row"><span class="field-key">Query Type:</span><span class="field-val">${app.query_type || 'A'}</span></div>
                        <div class="field-row"><span class="field-key">Response Code:</span><span class="field-val">${app.rcode_description || 'NOERROR'} (${app.rcode || 0})</span></div>
                        <div class="field-row"><span class="field-key">DNS Flags:</span><span class="field-val">${flagsList}</span></div>
                        <div class="field-row" style="grid-column: 1 / -1;"><span class="field-key">Answer Records:</span><span class="field-val">${ansList}</span></div>
                    `;
                } else if (app.protocol === "HTTP") {
                    appFields = `
                        <div class="field-row" style="grid-column: 1 / -1;"><span class="field-key">Request Line / Status:</span><span class="field-val">${app.request_line || p.summary}</span></div>
                        <div class="field-row"><span class="field-key">Payload Length:</span><span class="field-val">${app.payload_length_bytes || 0} Bytes</span></div>
                    `;
                } else {
                    appFields = `
                        <div class="field-row" style="grid-column: 1 / -1;"><span class="field-key">Classification:</span><span class="field-val">${p.application_protocol}</span></div>
                        <div class="field-row" style="grid-column: 1 / -1;"><span class="field-key">Note:</span><span class="field-val">${app.note || p.summary}</span></div>
                    `;
                }

                html += `
                    <div class="layer-card">
                        <div class="layer-card-title">Application Layer (Layer 7 - ${p.application_protocol})</div>
                        <div class="layer-card-content">
                            ${appFields}
                        </div>
                    </div>
                `;
            }

            elements.modalBody.innerHTML = html;
            elements.modal.style.display = "flex";
        } catch (err) {
            console.error("Modal fetch error:", err);
            showNotification(`Failed to load packet details: ${err.message}`, "error");
        }
    }

    elements.btnCloseModal.addEventListener("click", () => {
        elements.modal.style.display = "none";
    });

    // Close modal on escape key
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            if (elements.modal) elements.modal.style.display = "none";
            if (elements.configModal) elements.configModal.style.display = "none";
        }
    });

    // Close modal on backdrop click
    if (elements.modal) {
        elements.modal.addEventListener("click", (e) => {
            if (e.target === elements.modal) elements.modal.style.display = "none";
        });
    }
    if (elements.configModal) {
        elements.configModal.addEventListener("click", (e) => {
            if (e.target === elements.configModal) elements.configModal.style.display = "none";
        });
    }

    // Refresh all components
    async function refreshAll() {
        await Promise.all([
            refreshStats(),
            refreshProtocols(),
            refreshTimeline(),
            refreshTalkersAndFlows(),
            refreshAlerts(),
            refreshPackets(),
        ]);
    }

    // ==========================================================================
    // Event Listeners
    // ==========================================================================

    // Upload PCAP
    elements.pcapInput.addEventListener("change", async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append("file", file);

        showLoading(`Ingesting ${file.name}...`);
        elements.statusText.textContent = "Processing...";
        elements.statusDot.className = "status-dot status-running";

        try {
            const res = await fetch("/api/captures/upload", {
                method: "POST",
                body: formData,
            });
            const data = await res.json();

            if (res.ok) {
                showNotification(`Successfully ingested ${data.filename} (${data.summary.total_packets} packets).`, "info");
                elements.statusText.textContent = "Ready";
                elements.statusDot.className = "status-dot status-ready";
                elements.modeBadge.textContent = "Mode: Offline PCAP";
                elements.sessionBadge.textContent = data.filename;
                elements.sessionBadge.title = data.filename;
                state.currentPage = 1;
                await refreshAll();
            } else {
                showNotification(`Upload failed: ${data.error}`, "error", 6000);
                elements.statusText.textContent = "Error";
                elements.statusDot.className = "status-dot status-error";
            }
        } catch (err) {
            showNotification(`Upload network error: ${err.message}`, "error", 6000);
            elements.statusText.textContent = "Error";
            elements.statusDot.className = "status-dot status-error";
        } finally {
            hideLoading();
            elements.pcapInput.value = "";
        }
    });

    // Load Sample PCAP
    elements.btnLoadSample.addEventListener("click", async () => {
        showLoading("Loading sample capture dataset...");
        elements.statusText.textContent = "Loading Sample...";
        elements.statusDot.className = "status-dot status-running";

        try {
            const res = await fetch("/api/captures/load-sample", { method: "POST" });
            const data = await res.json();

            if (res.ok) {
                showNotification("Loaded multi-protocol sample capture (60 packets).", "info");
                elements.statusText.textContent = "Ready";
                elements.statusDot.className = "status-dot status-ready";
                elements.modeBadge.textContent = "Mode: Offline Sample";
                elements.sessionBadge.textContent = "sample_traffic.pcap";
                elements.sessionBadge.title = "sample_traffic.pcap";
                state.currentPage = 1;
                clearFlowFilter();
                await refreshAll();
            } else {
                showNotification(`Failed to load sample: ${data.error}`, "error");
                elements.statusText.textContent = "Error";
                elements.statusDot.className = "status-dot status-error";
            }
        } catch (err) {
            showNotification(`Sample load error: ${err.message}`, "error");
            elements.statusText.textContent = "Error";
            elements.statusDot.className = "status-dot status-error";
        } finally {
            hideLoading();
        }
    });

    // Open Threshold Config Modal
    function openConfigModal() {
        if (!elements.configModal) return;
        if (elements.configErrorMsg) elements.configErrorMsg.style.display = "none";
        fetch("/api/alerts/config")
            .then(r => r.json())
            .then(data => {
                const cfg = data.thresholds || {};
                elements.cfgSynFlood.value = cfg.syn_flood_threshold || 20;
                elements.cfgPortScan.value = cfg.port_scan_threshold || 15;
                elements.cfgPacketRate.value = cfg.packet_rate_threshold || 150;
                elements.cfgByteRate.value = cfg.byte_rate_threshold || 500000;
                elements.cfgHostRatio.value = cfg.host_volume_ratio || 0.5;
                elements.cfgCooldown.value = cfg.cooldown_seconds || 10;
                elements.configModal.style.display = "flex";
            })
            .catch(err => {
                showNotification(`Failed to load thresholds: ${err.message}`, "error");
            });
    }

    if (elements.btnOpenConfig) elements.btnOpenConfig.addEventListener("click", openConfigModal);
    if (elements.btnQuickConfig) elements.btnQuickConfig.addEventListener("click", openConfigModal);
    if (elements.btnCloseConfig) elements.btnCloseConfig.addEventListener("click", () => { elements.configModal.style.display = "none"; });
    if (elements.btnCancelConfig) elements.btnCancelConfig.addEventListener("click", () => { elements.configModal.style.display = "none"; });

    if (elements.btnSaveConfig) {
        elements.btnSaveConfig.addEventListener("click", async () => {
            const synFlood = parseInt(elements.cfgSynFlood.value);
            const portScan = parseInt(elements.cfgPortScan.value);
            const packetRate = parseInt(elements.cfgPacketRate.value);
            const byteRate = parseInt(elements.cfgByteRate.value);
            const hostRatio = parseFloat(elements.cfgHostRatio.value);
            const cooldown = parseInt(elements.cfgCooldown.value);

            // Client-side validation
            if (isNaN(synFlood) || synFlood < 2) {
                showConfigError("SYN burst threshold must be an integer >= 2.");
                return;
            }
            if (isNaN(portScan) || portScan < 2) {
                showConfigError("Port scan threshold must be an integer >= 2.");
                return;
            }
            if (isNaN(packetRate) || packetRate < 5) {
                showConfigError("Packet rate spike threshold must be >= 5 PPS.");
                return;
            }
            if (isNaN(byteRate) || byteRate < 500) {
                showConfigError("Bandwidth threshold must be >= 500 B/s.");
                return;
            }
            if (isNaN(hostRatio) || hostRatio <= 0.05 || hostRatio > 1.0) {
                showConfigError("Dominant host volume ratio must be between 0.1 and 1.0.");
                return;
            }
            if (isNaN(cooldown) || cooldown < 1) {
                showConfigError("Alert cooldown window must be >= 1 second.");
                return;
            }

            const payload = {
                syn_flood_threshold: synFlood,
                port_scan_threshold: portScan,
                packet_rate_threshold: packetRate,
                byte_rate_threshold: byteRate,
                host_volume_ratio: hostRatio,
                cooldown_seconds: cooldown,
            };

            try {
                const res = await fetch("/api/alerts/config", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                });
                const data = await res.json();
                if (res.ok) {
                    showNotification("Anomaly thresholds updated successfully.", "info");
                    elements.configModal.style.display = "none";
                    refreshAlerts();
                } else {
                    showConfigError(data.error || "Update rejected by server.");
                }
            } catch (err) {
                showConfigError(`Save error: ${err.message}`);
            }
        });
    }

    function showConfigError(msg) {
        if (!elements.configErrorMsg) return;
        elements.configErrorMsg.textContent = msg;
        elements.configErrorMsg.style.display = "block";
    }

    // Start Live Capture
    elements.btnStartLive.addEventListener("click", async () => {
        const iface = elements.interfaceSelect.value || null;
        showNotification("Starting live packet capture...", "info", 0);

        try {
            const res = await fetch("/api/captures/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ interface: iface }),
            });
            const data = await res.json();

            if (res.ok) {
                state.isCapturing = true;
                elements.btnStartLive.style.display = "none";
                elements.btnStopLive.style.display = "inline-flex";
                elements.statusText.textContent = "Capturing...";
                elements.statusDot.className = "status-dot status-running";
                elements.modeBadge.textContent = "Mode: Live Sniffer";
                elements.sessionBadge.textContent = iface ? `Interface: ${iface}` : "Default Interface";

                showNotification("Live capture running. Ingesting network frames...", "info", 3000);

                state.livePollInterval = setInterval(async () => {
                    await refreshAll();
                }, 1500);
            } else {
                showNotification(`Capture start failed: ${data.message || data.error}`, "error", 8000);
            }
        } catch (err) {
            showNotification(`Live capture network error: ${err.message}`, "error", 6000);
        }
    });

    // Stop Live Capture
    elements.btnStopLive.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/captures/stop", { method: "POST" });
            const data = await res.json();

            clearInterval(state.livePollInterval);
            state.isCapturing = false;

            elements.btnStartLive.style.display = "inline-flex";
            elements.btnStopLive.style.display = "none";
            elements.statusText.textContent = "Stopped";
            elements.statusDot.className = "status-dot status-ready";

            showNotification(data.message || "Live capture stopped.", "info");
            await refreshAll();
        } catch (err) {
            showNotification(`Stop capture error: ${err.message}`, "error");
        }
    });

    // Manual Refresh
    elements.btnRefresh.addEventListener("click", async () => {
        await refreshAll();
        showNotification("Dashboard analytics refreshed.", "info", 1500);
    });

    // Protocol Layer Selector
    elements.protocolLayerSelect.addEventListener("change", (e) => {
        state.protocolLayer = e.target.value;
        refreshProtocols();
    });

    // Timeline Unit Toggle (PPS <-> Kbps)
    elements.btnToggleTimeline.addEventListener("click", () => {
        state.timelineMetric = (state.timelineMetric === "pps") ? "kbps" : "pps";
        elements.btnToggleTimeline.textContent = (state.timelineMetric === "pps") ? "Switch Metric (Kbps)" : "Switch Metric (PPS)";
        refreshTimeline();
    });

    // Talker Tabs
    document.querySelectorAll("#talker-tabs .tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("#talker-tabs .tab-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            state.talkerTab = btn.dataset.tab;
            refreshTalkersAndFlows();
        });
    });

    // Filters & Search Debounce
    let debounceTimer = null;
    function triggerFilterUpdate() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            state.filters.search = elements.filterSearch.value.trim();
            state.filters.protocol = elements.filterProtocol.value;
            state.filters.pkt_id = elements.filterPktId.value.trim();
            state.filters.src_ip = elements.filterSrcIp.value.trim();
            state.filters.dst_ip = elements.filterDstIp.value.trim();
            state.filters.src_port = elements.filterSrcPort.value.trim();
            state.filters.dst_port = elements.filterDstPort.value.trim();
            state.currentPage = 1;
            refreshPackets();
        }, 200);
    }

    elements.filterSearch.addEventListener("input", triggerFilterUpdate);
    elements.filterProtocol.addEventListener("change", triggerFilterUpdate);
    elements.filterPktId.addEventListener("input", triggerFilterUpdate);
    elements.filterSrcIp.addEventListener("input", triggerFilterUpdate);
    elements.filterDstIp.addEventListener("input", triggerFilterUpdate);
    elements.filterSrcPort.addEventListener("input", triggerFilterUpdate);
    elements.filterDstPort.addEventListener("input", triggerFilterUpdate);

    // Reset Filters
    elements.btnResetFilters.addEventListener("click", () => {
        elements.filterSearch.value = "";
        elements.filterProtocol.value = "";
        elements.filterPktId.value = "";
        elements.filterSrcIp.value = "";
        elements.filterDstIp.value = "";
        elements.filterSrcPort.value = "";
        elements.filterDstPort.value = "";
        clearFlowFilter();
        state.filters = { search: "", protocol: "", pkt_id: "", src_ip: "", dst_ip: "", src_port: "", dst_port: "", flow_id: "" };
        state.currentPage = 1;
        refreshPackets();
        showNotification("All active filters cleared.", "info", 1500);
    });

    // Export CSV
    elements.btnExportCsv.addEventListener("click", () => {
        const params = new URLSearchParams({
            search: state.filters.search,
            protocol: state.filters.protocol,
            src_ip: state.filters.src_ip,
            dst_ip: state.filters.dst_ip,
        });
        if (state.filters.pkt_id) params.append("packet_id", state.filters.pkt_id);
        if (state.filters.src_port) params.append("src_port", state.filters.src_port);
        if (state.filters.dst_port) params.append("dst_port", state.filters.dst_port);
        if (state.filters.flow_id) params.append("flow_id", state.filters.flow_id);

        window.location.href = `/api/export/csv?${params.toString()}`;
    });

    // Pagination
    elements.btnPrevPage.addEventListener("click", () => {
        if (state.currentPage > 1) {
            state.currentPage--;
            refreshPackets();
        }
    });

    elements.btnNextPage.addEventListener("click", () => {
        state.currentPage++;
        refreshPackets();
    });

    elements.pageSizeSelect.addEventListener("change", (e) => {
        state.pageSize = parseInt(e.target.value);
        state.currentPage = 1;
        refreshPackets();
    });

    // Table Column Sorting
    document.querySelectorAll(".packet-table th[data-sort]").forEach(th => {
        th.addEventListener("click", () => {
            const sortField = th.dataset.sort;
            if (state.sortBy === sortField) {
                state.sortOrder = (state.sortOrder === "asc") ? "desc" : "asc";
            } else {
                state.sortBy = sortField;
                state.sortOrder = "asc";
            }
            refreshPackets();
        });
    });

    // ==========================================================================
    // NetScope 3.0: TCP Conversation Timeline
    // ==========================================================================
    async function openFlowTimeline(flowId) {
        if (!elements.modalFlowTimeline) return;
        elements.modalFlowTitle.textContent = `TCP Conversation Inspector — ${flowId}`;
        elements.modalFlowSubtitle.textContent = "Loading conversation events...";
        elements.flowTimelineTbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Fetching flow timeline...</td></tr>';
        elements.modalFlowTimeline.style.display = "flex";

        try {
            const res = await fetch(`/api/flows/${flowId}/timeline`);
            if (!res.ok) {
                elements.flowTimelineTbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Failed to load timeline for ${flowId}.</td></tr>`;
                return;
            }
            const data = await res.json();
            elements.modalFlowSubtitle.textContent = `${data.endpoint_a} ↔ ${data.endpoint_b} | ${data.transport_protocol} (${data.application_protocol || 'Unclassified'})`;

            elements.flowChipHandshake.textContent = data.handshake_status || "Not Applicable";
            elements.flowChipState.textContent = data.tcp_state || "STATELESS";
            elements.flowChipRetrans.textContent = `${data.retransmissions || 0} Retransmissions`;
            elements.flowChipVolume.textContent = `${data.total_packets} pkts (${formatBytes(data.total_bytes)})`;
            elements.flowChipDuration.textContent = `${(data.duration || 0).toFixed(3)}s`;

            if (elements.btnFlowFilterExplorer) {
                elements.btnFlowFilterExplorer.onclick = () => {
                    elements.modalFlowTimeline.style.display = "none";
                    applyFlowFilter(data.flow_id);
                };
            }

            const events = data.timeline || [];
            if (events.length === 0) {
                elements.flowTimelineTbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No chronological events recorded for this conversation.</td></tr>';
            } else {
                elements.flowTimelineTbody.innerHTML = "";
                events.forEach(evt => {
                    const tr = document.createElement("tr");
                    const isFwd = evt.direction.includes("A -> B");
                    const dirClass = isFwd ? "dir-ab" : "dir-ba";
                    const dirIcon = isFwd ? "→" : "←";
                    
                    let eventBadgeClass = "event-ack";
                    const et = (evt.event_type || "").toUpperCase();
                    if (et === "SYN") eventBadgeClass = "event-syn";
                    else if (et === "SYN-ACK") eventBadgeClass = "event-syn-ack";
                    else if (et.includes("DATA")) eventBadgeClass = "event-data";
                    else if (et === "FIN") eventBadgeClass = "event-fin";
                    else if (et === "RST") eventBadgeClass = "event-rst";

                    tr.innerHTML = `
                        <td class="mono" style="font-size:11px;">+${(evt.relative_time_sec || 0).toFixed(4)}s</td>
                        <td><span class="dir-indicator ${dirClass}">${dirIcon} ${evt.direction}</span></td>
                        <td>
                            <span class="event-badge ${eventBadgeClass}">${evt.event_type}</span>
                            ${evt.is_retransmission ? '<span class="badge-retrans">RETRANS</span>' : ''}
                        </td>
                        <td class="mono" style="font-size:11px;">${evt.tcp_seq !== null && evt.tcp_seq !== undefined ? evt.tcp_seq : '-'}</td>
                        <td class="mono" style="font-size:11px;">${evt.tcp_ack !== null && evt.tcp_ack !== undefined ? evt.tcp_ack : '-'}</td>
                        <td class="mono" style="font-size:11px;">${evt.packet_length || 0} B</td>
                        <td>
                            <button class="btn btn-outline btn-xs btn-inspect-frame" data-pkt-id="${evt.packet_id}">#${evt.packet_id}</button>
                        </td>
                    `;
                    elements.flowTimelineTbody.appendChild(tr);
                });

                // Attach frame click listeners
                elements.flowTimelineTbody.querySelectorAll(".btn-inspect-frame").forEach(btn => {
                    btn.addEventListener("click", (e) => {
                        const pid = parseInt(e.target.dataset.pktId);
                        inspectPacket(pid);
                    });
                });
            }
        } catch (err) {
            console.error("Flow timeline error:", err);
            elements.flowTimelineTbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error: ${err.message}</td></tr>`;
        }
    }

    if (elements.btnCloseFlowTimeline) {
        elements.btnCloseFlowTimeline.addEventListener("click", () => {
            elements.modalFlowTimeline.style.display = "none";
        });
    }

    // ==========================================================================
    // NetScope 3.0: Capture Comparison
    // ==========================================================================
    function openCompareModal() {
        if (!elements.modalCompare) return;
        elements.modalCompare.style.display = "flex";
    }

    async function runCaptureComparison(formData) {
        showLoading("Executing differential comparative analysis...");
        try {
            const res = await fetch("/api/captures/compare", {
                method: "POST",
                body: formData,
            });
            const data = await res.json();
            hideLoading();

            if (!res.ok) {
                showNotification(data.error || "Capture comparison failed.", "error");
                return;
            }

            renderComparisonResults(data);
        } catch (err) {
            hideLoading();
            showNotification(`Comparison failed: ${err.message}`, "error");
        }
    }

    function renderComparisonResults(data) {
        elements.comparePlaceholder.style.display = "none";
        elements.compareResults.style.display = "block";

        elements.cmpNameA.textContent = data.capture_a.filename;
        elements.cmpNameB.textContent = data.capture_b.filename;

        if (data.duration_warning) {
            elements.compareWarningBanner.textContent = data.duration_warning;
            elements.compareWarningBanner.style.display = "block";
        } else {
            elements.compareWarningBanner.style.display = "none";
        }

        const m = data.metrics || {};
        const metricLabels = {
            total_packets: "Total Ingested Frames",
            total_bytes: "Captured Volume (Bytes)",
            capture_duration_seconds: "Capture Duration (Seconds)",
            capture_pps: "Packet Arrival Rate (PPS)",
            throughput_kbps: "Average Throughput (kbps)",
            average_packet_size_bytes: "Average Frame Size (Bytes)",
            unique_hosts: "Unique Host Endpoints",
            active_flows: "Canonical 5-Tuple Flows",
            alerts_count: "Heuristic Anomaly Alerts",
            processing_pps: "Engine Processing Speed (PPS)",
        };

        elements.compareMetricsTbody.innerHTML = "";
        for (const [key, label] of Object.entries(metricLabels)) {
            const item = m[key];
            if (!item) continue;

            const tr = document.createElement("tr");
            const pct = item.pct_change || 0;
            let pillClass = "delta-zero";
            let sign = "";
            if (pct > 0) { pillClass = "delta-positive"; sign = "+"; }
            else if (pct < 0) { pillClass = "delta-negative"; }

            tr.innerHTML = `
                <td><strong>${label}</strong></td>
                <td class="mono">${typeof item.val_a === 'number' ? item.val_a.toLocaleString() : item.val_a}</td>
                <td class="mono">${typeof item.val_b === 'number' ? item.val_b.toLocaleString() : item.val_b}</td>
                <td class="mono">${item.diff > 0 ? '+' : ''}${typeof item.diff === 'number' ? item.diff.toLocaleString() : item.diff}</td>
                <td><span class="delta-pill ${pillClass}">${sign}${pct.toFixed(1)}%</span></td>
            `;
            elements.compareMetricsTbody.appendChild(tr);
        }

        const protoShifts = data.protocol_shifts?.transport || [];
        elements.compareProtocolsTbody.innerHTML = "";
        if (protoShifts.length === 0) {
            elements.compareProtocolsTbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No protocol differences recorded.</td></tr>';
        } else {
            protoShifts.forEach(ps => {
                const tr = document.createElement("tr");
                const diff = ps.pct_diff || 0;
                let pillClass = "delta-zero";
                let sign = "";
                if (diff > 0) { pillClass = "delta-positive"; sign = "+"; }
                else if (diff < 0) { pillClass = "delta-negative"; }

                tr.innerHTML = `
                    <td><strong>${ps.protocol}</strong></td>
                    <td class="mono">${ps.pct_a.toFixed(1)}% (${ps.count_a} pkts)</td>
                    <td class="mono">${ps.pct_b.toFixed(1)}% (${ps.count_b} pkts)</td>
                    <td><span class="delta-pill ${pillClass}">${sign}${diff.toFixed(1)}% shift</span></td>
                `;
                elements.compareProtocolsTbody.appendChild(tr);
            });
        }
    }

    if (elements.btnOpenCompare) {
        elements.btnOpenCompare.addEventListener("click", openCompareModal);
    }
    if (elements.btnCloseCompare) {
        elements.btnCloseCompare.addEventListener("click", () => {
            elements.modalCompare.style.display = "none";
        });
    }
    if (elements.btnCompareWithSample) {
        elements.btnCompareWithSample.addEventListener("click", () => {
            const fd = new FormData();
            fd.append("compare_sample", "true");
            runCaptureComparison(fd);
        });
    }
    if (elements.compareFileInput) {
        elements.compareFileInput.addEventListener("change", (e) => {
            const f = e.target.files[0];
            if (f) {
                const fd = new FormData();
                fd.append("file_b", f);
                runCaptureComparison(fd);
            }
        });
    }

    // ==========================================================================
    // NetScope 3.0: Report Download
    // ==========================================================================
    if (elements.btnDownloadReport) {
        elements.btnDownloadReport.addEventListener("click", () => {
            window.open("/api/export/report", "_blank");
        });
    }

    // Global Modal Escape Key Listener
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            if (elements.modalFlowTimeline) elements.modalFlowTimeline.style.display = "none";
            if (elements.modalCompare) elements.modalCompare.style.display = "none";
            if (elements.modal) elements.modal.style.display = "none";
            if (elements.configModal) elements.configModal.style.display = "none";
        }
    });

    // ==========================================================================
    // Initialization
    // ==========================================================================
    initTheme();
    refreshInterfaces();
    refreshAll();

    // Check URL parameters for direct deep-linking or automated capture
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("theme")) {
        setTheme(urlParams.get("theme"));
    }
    const inspectPktId = urlParams.get("inspect");
    if (inspectPktId) {
        setTimeout(() => {
            inspectPacket(parseInt(inspectPktId));
        }, 800);
    }
    const inspectFlowId = urlParams.get("inspect_flow");
    if (inspectFlowId) {
        setTimeout(() => {
            openFlowTimeline(inspectFlowId);
        }, 800);
    }
    const openCompare = urlParams.get("open_compare");
    if (openCompare) {
        setTimeout(async () => {
            openCompareModal();
            const fd = new FormData();
            fd.append("compare_sample", "true");
            await runCaptureComparison(fd);
        }, 800);
    }
    const scrollToSection = urlParams.get("section");
    if (scrollToSection) {
        setTimeout(() => {
            const el = document.getElementById(scrollToSection);
            if (el) el.scrollIntoView({ behavior: "instant", block: "start" });
        }, 800);
    }
});
