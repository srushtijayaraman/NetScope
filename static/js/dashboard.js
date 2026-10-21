/**
 * NetScope Dashboard Controller (Enhanced Version)
 * Asynchronous state orchestration, safe DOM rendering, flow filtering,
 * alert packet linking, heuristic threshold management, and real-time backend synchronization.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Global State
    const state = {
        currentPage: 1,
        pageSize: 50,
        sortBy: "packet_id",
        sortOrder: "asc",
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
        interfaceSelect: document.getElementById("interface-select"),
        btnStartLive: document.getElementById("btn-start-live"),
        btnStopLive: document.getElementById("btn-stop-live"),
        btnRefresh: document.getElementById("btn-refresh"),
        protocolLayerSelect: document.getElementById("protocol-layer-select"),
        btnToggleTimeline: document.getElementById("btn-toggle-timeline-unit"),

        // Tables & Lists
        topTalkersThead: document.getElementById("top-talkers-thead"),
        topTalkersTbody: document.getElementById("top-talkers-tbody"),
        flowsTbody: document.getElementById("flows-tbody"),
        flowCountBadge: document.getElementById("flow-count-badge"),
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
        btnCloseConfig: document.getElementById("btn-close-config"),
        btnCancelConfig: document.getElementById("btn-cancel-config"),
        btnSaveConfig: document.getElementById("btn-save-config"),
        cfgSynFlood: document.getElementById("cfg-syn-flood"),
        cfgPortScan: document.getElementById("cfg-port-scan"),
        cfgPacketRate: document.getElementById("cfg-packet-rate"),
        cfgByteRate: document.getElementById("cfg-byte-rate"),
        cfgHostRatio: document.getElementById("cfg-host-ratio"),
        cfgCooldown: document.getElementById("cfg-cooldown"),
    };

    // Helper: Format Bytes
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    // Helper: Show Banner
    function showNotification(msg, type = "info", duration = 4000) {
        elements.banner.textContent = msg;
        elements.banner.className = `notification-banner ${type}`;
        elements.banner.style.display = "flex";
        if (duration > 0) {
            setTimeout(() => {
                elements.banner.style.display = "none";
            }, duration);
        }
    }

    function showLoading(msg = "Processing capture...") {
        elements.loadingText.textContent = msg;
        elements.loadingOverlay.style.display = "flex";
    }

    function hideLoading() {
        elements.loadingOverlay.style.display = "none";
    }

    // 1. Fetch Interface Capabilities
    async function loadInterfaces() {
        try {
            const res = await fetch("/api/interfaces");
            const data = await res.json();
            elements.interfaceSelect.innerHTML = '<option value="">Default Interface</option>';
            if (data.interfaces && data.interfaces.length > 0) {
                data.interfaces.forEach(iface => {
                    const opt = document.createElement("option");
                    opt.value = iface.id;
                    opt.textContent = `${iface.name} (${iface.ip})`;
                    elements.interfaceSelect.appendChild(opt);
                });
            }
            if (!data.supported) {
                elements.btnStartLive.title = data.message;
            }
        } catch (err) {
            console.error("Interface check failed:", err);
        }
    }

    // 2. Fetch High-Level Stats
    async function refreshStats() {
        try {
            const res = await fetch("/api/stats");
            const data = await res.json();

            elements.totalPackets.textContent = (data.total_packets || 0).toLocaleString();
            elements.processingPps.textContent = `Processing: ${(data.processing_pps || 0).toLocaleString()} pps`;
            elements.totalBytes.textContent = formatBytes(data.total_bytes);
            elements.avgPacketSize.textContent = `Avg Size: ${(data.average_packet_size_bytes || 0).toFixed(1)} B`;
            elements.capturePps.innerHTML = `${(data.capture_pps || 0).toFixed(1)} <span class="unit">pps</span>`;
            elements.captureDuration.textContent = `Span: ${(data.capture_duration_seconds || 0).toFixed(2)}s`;
            elements.throughput.innerHTML = `${(data.throughput_kbps || 0).toFixed(2)} <span class="unit">kbps</span>`;
            elements.throughputMbps.textContent = `${(data.throughput_mbps || 0).toFixed(4)} Mbps`;
            elements.uniqueHosts.textContent = data.unique_hosts || 0;
            elements.activeFlows.textContent = `${data.active_flows || 0} Active Flows`;
            elements.errorsDrops.textContent = `${data.parsing_errors || 0} / ${data.queue_drops || 0}`;
        } catch (err) {
            console.error("Stats refresh error:", err);
        }
    }

    // 3. Fetch Protocols & Render Chart
    async function refreshProtocols() {
        try {
            const res = await fetch("/api/protocols");
            const data = await res.json();
            NetScopeCharts.renderProtocolChart(data, state.protocolLayer);
        } catch (err) {
            console.error("Protocol refresh error:", err);
        }
    }

    // 4. Fetch Timeline & Render Chart
    async function refreshTimeline() {
        try {
            const res = await fetch("/api/traffic-timeline");
            const data = await res.json();
            NetScopeCharts.renderTimelineChart(data.timeline, state.timelineMetric);
        } catch (err) {
            console.error("Timeline refresh error:", err);
        }
    }

    // 5. Fetch Top Talkers & Flows
    async function refreshTalkersAndFlows() {
        try {
            const res = await fetch("/api/top-talkers?limit=8");
            const data = await res.json();

            // Render Talkers Table
            const talkers = data.talkers || {};
            elements.topTalkersTbody.innerHTML = "";

            if (state.talkerTab === "sources" || state.talkerTab === "destinations") {
                elements.topTalkersThead.innerHTML = "<th>IP Address</th><th>Packets</th><th>Volume</th>";
                const list = (state.talkerTab === "sources" ? talkers.sources : talkers.destinations) || [];
                if (list.length === 0) {
                    elements.topTalkersTbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No talker data.</td></tr>';
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
                const ports = data.top_ports || [];
                if (ports.length === 0) {
                    elements.topTalkersTbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No port data.</td></tr>';
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

            // Bind click-to-filter on talker IPs and ports
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

            // Render Flows with Filter Button
            const flows = data.top_flows || [];
            elements.flowCountBadge.textContent = `${flows.length} Flows`;
            elements.flowsTbody.innerHTML = "";
            if (flows.length === 0) {
                elements.flowsTbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No flows recorded.</td></tr>';
            } else {
                flows.forEach(f => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td class="mono"><strong>${f.flow_id}</strong></td>
                        <td class="mono">${f.endpoint_a} &harr; ${f.endpoint_b}</td>
                        <td><span class="badge badge-proto badge-tcp">${f.transport_protocol}</span></td>
                        <td class="mono">${f.duration.toFixed(2)}s</td>
                        <td class="mono">${f.total_packets}</td>
                        <td class="mono">${formatBytes(f.total_bytes)}</td>
                        <td><span class="badge">${f.tcp_state}</span></td>
                        <td><button class="btn btn-outline btn-xs btn-filter-flow" data-flow-id="${f.flow_id}">Filter Flow</button></td>
                    `;
                    elements.flowsTbody.appendChild(tr);
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
            console.error("Talkers/Flows error:", err);
        }
    }

    function applyFlowFilter(flowId) {
        state.filters.flow_id = flowId;
        elements.activeFlowId.textContent = flowId;
        elements.activeFlowBadge.style.display = "inline-block";
        state.currentPage = 1;
        refreshPackets();
        document.querySelector(".packet-explorer-card").scrollIntoView({ behavior: "smooth" });
        showNotification(`Filtered packet explorer to ${flowId}`, "info", 2500);
    }

    function clearFlowFilter() {
        state.filters.flow_id = "";
        elements.activeFlowBadge.style.display = "none";
        state.currentPage = 1;
        refreshPackets();
    }

    elements.activeFlowBadge.addEventListener("click", clearFlowFilter);

    // 6. Fetch Security Alerts with Packet References
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
                item.className = `alert-item severity-${alt.severity}`;
                
                const natureBadge = alt.classification_nature ? `<span class="badge" style="font-size:10px;">${alt.classification_nature}</span>` : '';
                
                let pktRefsHtml = '';
                if (alt.packet_references && alt.packet_references.length > 0) {
                    const sampleRefs = alt.packet_references.slice(0, 8).map(id => `#${id}`).join(", ");
                    const more = alt.packet_references.length > 8 ? ` (+${alt.packet_references.length - 8} more)` : '';
                    pktRefsHtml = `<div style="margin-top:4px;"><a href="javascript:void(0)" class="alert-pkt-link" data-host="${alt.host}" style="color:var(--accent-blue); text-decoration:underline;">Inspect Supporting Packets: ${sampleRefs}${more}</a></div>`;
                }

                item.innerHTML = `
                    <div class="alert-main">
                        <div class="alert-title-row">
                            <span class="badge ${alt.severity === 'HIGH' ? 'badge-danger' : 'badge-warning'}">${alt.severity}</span>
                            <span class="alert-title">${alt.alert_type}</span>
                            ${natureBadge}
                        </div>
                        <div class="alert-desc">${alt.explanation}</div>
                        ${pktRefsHtml}
                    </div>
                    <div class="alert-meta">
                        <div>Host: ${alt.host}</div>
                        <div>Observed: ${alt.observed_value || alt.observed_metric}</div>
                        <div class="text-muted">Threshold: ${alt.threshold || alt.configured_threshold}</div>
                        <div class="text-muted">${alt.time_window || ''}</div>
                    </div>
                `;
                elements.alertsContainer.appendChild(item);
            });

            // Bind click on alert packet links
            elements.alertsContainer.querySelectorAll(".alert-pkt-link").forEach(a => {
                a.addEventListener("click", (e) => {
                    const host = e.target.dataset.host;
                    elements.filterSrcIp.value = host;
                    state.filters.src_ip = host;
                    state.currentPage = 1;
                    refreshPackets();
                    document.querySelector(".packet-explorer-card").scrollIntoView({ behavior: "smooth" });
                    showNotification(`Filtering packet explorer to suspect host ${host}`, "info", 3000);
                });
            });
        } catch (err) {
            console.error("Alerts error:", err);
        }
    }

    // 7. Fetch Packets (Explorer Grid)
    async function refreshPackets() {
        try {
            const params = new URLSearchParams({
                page: state.currentPage,
                limit: state.pageSize,
                sort_by: state.sortBy,
                sort_order: state.sortOrder,
                search: state.filters.search,
                protocol: state.filters.protocol,
                src_ip: state.filters.src_ip,
                dst_ip: state.filters.dst_ip,
            });
            if (state.filters.pkt_id) {
                params.append("packet_id", state.filters.pkt_id);
            }
            if (state.filters.src_port) {
                params.append("src_port", state.filters.src_port);
            }
            if (state.filters.dst_port) {
                params.append("dst_port", state.filters.dst_port);
            }
            if (state.filters.flow_id) {
                params.append("flow_id", state.filters.flow_id);
            }

            const res = await fetch(`/api/packets?${params.toString()}`);
            const data = await res.json();

            elements.packetFilterCount.textContent = `Showing ${data.packets.length} of ${data.total} packets`;
            elements.paginationInfo.textContent = `Page ${data.page} of ${data.pages} (${data.total.toLocaleString()} total packets)`;
            elements.pageDisplay.textContent = data.page;

            elements.btnPrevPage.disabled = (data.page <= 1);
            elements.btnNextPage.disabled = (data.page >= data.pages);

            elements.packetTableBody.innerHTML = "";
            if (!data.packets || data.packets.length === 0) {
                elements.packetTableBody.innerHTML = '<tr><td colspan="12" class="text-center text-muted">No matching packets found.</td></tr>';
                return;
            }

            data.packets.forEach(pkt => {
                const tr = document.createElement("tr");
                tr.dataset.packetId = pkt.packet_id;

                const protoClass = (pkt.transport_protocol || pkt.network_protocol || "").toLowerCase();
                const appProtoBadge = pkt.application_protocol && pkt.application_protocol !== "Unknown" && pkt.application_protocol !== "None"
                    ? `<span class="badge badge-proto badge-${pkt.application_protocol.toLowerCase()}">${pkt.application_protocol}</span>`
                    : '<span class="text-muted">-</span>';

                const flags = (pkt.tcp_flags && pkt.tcp_flags.length > 0)
                    ? `<span class="badge mono">[${pkt.tcp_flags.join(",")}]</span>`
                    : '<span class="text-muted">-</span>';

                // Safe DOM cell construction
                const tdId = document.createElement("td");
                tdId.className = "mono";
                tdId.textContent = pkt.packet_id;

                const tdFlow = document.createElement("td");
                tdFlow.className = "mono";
                tdFlow.innerHTML = pkt.flow_id ? `<span class="badge" style="font-size:10px;">${pkt.flow_id}</span>` : '<span class="text-muted">-</span>';

                const tdTime = document.createElement("td");
                tdTime.className = "mono";
                tdTime.textContent = pkt.timestamp_iso ? pkt.timestamp_iso.split(" ")[1] : "00:00:00.000";

                const tdRel = document.createElement("td");
                tdRel.className = "mono text-muted";
                tdRel.textContent = `+${(pkt.relative_time_sec || 0).toFixed(3)}s`;

                const tdSrc = document.createElement("td");
                tdSrc.className = "mono";
                tdSrc.textContent = pkt.source_port ? `${pkt.source_ip}:${pkt.source_port}` : (pkt.source_ip || "-");

                const tdDst = document.createElement("td");
                tdDst.className = "mono";
                tdDst.textContent = pkt.destination_port ? `${pkt.destination_ip}:${pkt.destination_port}` : (pkt.destination_ip || "-");

                const tdNet = document.createElement("td");
                tdNet.innerHTML = `<span class="badge badge-proto">${pkt.network_protocol}</span>`;

                const tdTrans = document.createElement("td");
                tdTrans.innerHTML = `<span class="badge badge-proto badge-${protoClass}">${pkt.transport_protocol}</span>`;

                const tdApp = document.createElement("td");
                tdApp.innerHTML = appProtoBadge;

                const tdLen = document.createElement("td");
                tdLen.className = "mono";
                tdLen.textContent = `${pkt.packet_length} B`;

                const tdFlags = document.createElement("td");
                tdFlags.innerHTML = flags;

                const tdInfo = document.createElement("td");
                tdInfo.className = "mono text-muted";
                tdInfo.textContent = pkt.summary;
                tdInfo.title = pkt.summary;

                tr.appendChild(tdId);
                tr.appendChild(tdFlow);
                tr.appendChild(tdTime);
                tr.appendChild(tdRel);
                tr.appendChild(tdSrc);
                tr.appendChild(tdDst);
                tr.appendChild(tdNet);
                tr.appendChild(tdTrans);
                tr.appendChild(tdApp);
                tr.appendChild(tdLen);
                tr.appendChild(tdFlags);
                tr.appendChild(tdInfo);

                tr.addEventListener("click", () => openPacketModal(pkt.packet_id));
                elements.packetTableBody.appendChild(tr);
            });
        } catch (err) {
            console.error("Packets fetch error:", err);
        }
    }

    // 8. Open Packet Details Modal
    async function openPacketModal(packetId) {
        try {
            const res = await fetch(`/api/packets/${packetId}`);
            if (!res.ok) {
                showNotification("Packet details not found.", "error");
                return;
            }
            const pkt = await res.json();
            elements.modalTitle.textContent = `Packet #${pkt.packet_id} Detailed Protocol Inspection`;

            const d = pkt.details || {};
            let html = "";

            // Summary row
            html += `
                <div class="layer-card">
                    <div class="layer-card-title">Frame Overview</div>
                    <div class="layer-card-content">
                        <div class="field-row"><span class="field-key">Packet ID:</span><span class="field-val">#${pkt.packet_id}</span></div>
                        <div class="field-row"><span class="field-key">Flow ID:</span><span class="field-val">${pkt.flow_id || 'N/A'}</span></div>
                        <div class="field-row"><span class="field-key">Timestamp UTC:</span><span class="field-val">${pkt.timestamp_iso}</span></div>
                        <div class="field-row"><span class="field-key">Relative Time:</span><span class="field-val">+${(pkt.relative_time_sec || 0).toFixed(4)}s</span></div>
                        <div class="field-row"><span class="field-key">Wire Length:</span><span class="field-val">${pkt.packet_length} Bytes (${pkt.packet_length * 8} bits)</span></div>
                        <div class="field-row"><span class="field-key">Parsing Status:</span><span class="field-val">${pkt.parsing_status}</span></div>
                        <div class="field-row" style="grid-column: 1 / -1;"><span class="field-key">Summary:</span><span class="field-val">${pkt.summary}</span></div>
                    </div>
                </div>
            `;

            // Link Layer
            if (d.link_layer && Object.keys(d.link_layer).length > 0) {
                html += `
                    <div class="layer-card">
                        <div class="layer-card-title">Link Layer (${d.link_layer.type || 'Ethernet'})</div>
                        <div class="layer-card-content">
                            <div class="field-row"><span class="field-key">Source MAC:</span><span class="field-val">${d.link_layer.source_mac || 'N/A'}</span></div>
                            <div class="field-row"><span class="field-key">Destination MAC:</span><span class="field-val">${d.link_layer.destination_mac || 'N/A'}</span></div>
                            <div class="field-row"><span class="field-key">EtherType:</span><span class="field-val">${d.link_layer.ether_type || 'N/A'}</span></div>
                        </div>
                    </div>
                `;
            }

            // Network Layer
            if (d.network_layer && Object.keys(d.network_layer).length > 0) {
                const net = d.network_layer;
                html += `
                    <div class="layer-card">
                        <div class="layer-card-title">Network Layer (${net.protocol || pkt.network_protocol})</div>
                        <div class="layer-card-content">
                            <div class="field-row"><span class="field-key">Source IP:</span><span class="field-val">${net.source_ip || net.sender_ip || 'N/A'}</span></div>
                            <div class="field-row"><span class="field-key">Destination IP:</span><span class="field-val">${net.destination_ip || net.target_ip || 'N/A'}</span></div>
                            ${net.ttl !== undefined && net.ttl !== null ? `<div class="field-row"><span class="field-key">TTL (Time to Live):</span><span class="field-val">${net.ttl}</span></div>` : ''}
                            ${net.identification !== undefined && net.identification !== null ? `<div class="field-row"><span class="field-key">Identification:</span><span class="field-val">${net.identification}</span></div>` : ''}
                            ${net.fragment_offset !== undefined ? `<div class="field-row"><span class="field-key">Fragment Offset:</span><span class="field-val">${net.fragment_offset}</span></div>` : ''}
                            ${net.flags ? `<div class="field-row"><span class="field-key">IP Flags:</span><span class="field-val">${net.flags}</span></div>` : ''}
                            ${net.checksum ? `<div class="field-row"><span class="field-key">Header Checksum:</span><span class="field-val">${net.checksum}</span></div>` : ''}
                            ${net.operation ? `<div class="field-row"><span class="field-key">ARP Operation:</span><span class="field-val">${net.operation}</span></div>` : ''}
                            ${net.hop_limit ? `<div class="field-row"><span class="field-key">IPv6 Hop Limit:</span><span class="field-val">${net.hop_limit}</span></div>` : ''}
                        </div>
                    </div>
                `;
            }

            // Transport Layer
            if (d.transport_layer && Object.keys(d.transport_layer).length > 0) {
                const trans = d.transport_layer;
                html += `
                    <div class="layer-card">
                        <div class="layer-card-title">Transport Layer (${trans.protocol || pkt.transport_protocol})</div>
                        <div class="layer-card-content">
                            ${trans.source_port ? `<div class="field-row"><span class="field-key">Source Port:</span><span class="field-val">${trans.source_port}</span></div>` : ''}
                            ${trans.destination_port ? `<div class="field-row"><span class="field-key">Destination Port:</span><span class="field-val">${trans.destination_port}</span></div>` : ''}
                            ${trans.sequence_number !== undefined ? `<div class="field-row"><span class="field-key">Sequence Number:</span><span class="field-val">${trans.sequence_number}</span></div>` : ''}
                            ${trans.acknowledgment_number !== undefined ? `<div class="field-row"><span class="field-key">Acknowledgment Number:</span><span class="field-val">${trans.acknowledgment_number}</span></div>` : ''}
                            ${trans.flags ? `<div class="field-row"><span class="field-key">TCP Flags:</span><span class="field-val">${trans.flags.join(", ")} (${trans.flags_hex || ''})</span></div>` : ''}
                            ${trans.window_size !== undefined ? `<div class="field-row"><span class="field-key">Window Size:</span><span class="field-val">${trans.window_size}</span></div>` : ''}
                            ${trans.type_name ? `<div class="field-row"><span class="field-key">ICMP Message:</span><span class="field-val">${trans.type_name} (Code ${trans.code})</span></div>` : ''}
                            ${trans.id !== undefined && trans.id !== null ? `<div class="field-row"><span class="field-key">ICMP Identifier:</span><span class="field-val">${trans.id}</span></div>` : ''}
                            ${trans.sequence !== undefined && trans.sequence !== null ? `<div class="field-row"><span class="field-key">ICMP Sequence:</span><span class="field-val">${trans.sequence}</span></div>` : ''}
                            ${trans.checksum ? `<div class="field-row"><span class="field-key">Checksum:</span><span class="field-val">${trans.checksum}</span></div>` : ''}
                        </div>
                    </div>
                `;
            }

            // Application Layer
            if (d.application_layer && Object.keys(d.application_layer).length > 0) {
                const app = d.application_layer;
                html += `
                    <div class="layer-card">
                        <div class="layer-card-title">Application Layer (${app.protocol || pkt.application_protocol})</div>
                        <div class="layer-card-content">
                            ${app.transaction_id ? `<div class="field-row"><span class="field-key">Transaction ID:</span><span class="field-val">${app.transaction_id}</span></div>` : ''}
                            ${app.message_type ? `<div class="field-row"><span class="field-key">DNS Message Type:</span><span class="field-val">${app.message_type}</span></div>` : ''}
                            ${app.query_name ? `<div class="field-row"><span class="field-key">DNS Query Name:</span><span class="field-val">${app.query_name}</span></div>` : ''}
                            ${app.query_type ? `<div class="field-row"><span class="field-key">DNS Query Type:</span><span class="field-val">${app.query_type}</span></div>` : ''}
                            ${app.rcode_description ? `<div class="field-row"><span class="field-key">Response Code:</span><span class="field-val">${app.rcode_description}</span></div>` : ''}
                            ${app.dns_flags && app.dns_flags.length > 0 ? `<div class="field-row"><span class="field-key">DNS Flags:</span><span class="field-val">${app.dns_flags.join(", ")}</span></div>` : ''}
                            ${app.answers && app.answers.length > 0 ? `<div class="field-row" style="grid-column: 1 / -1;"><span class="field-key">DNS Resolved Answers:</span><span class="field-val">${app.answers.join("<br/>")}</span></div>` : ''}
                            ${app.request_line ? `<div class="field-row" style="grid-column: 1 / -1;"><span class="field-key">HTTP Request Line:</span><span class="field-val">${app.request_line}</span></div>` : ''}
                            ${app.payload_length_bytes !== undefined ? `<div class="field-row"><span class="field-key">Payload Length:</span><span class="field-val">${app.payload_length_bytes} Bytes</span></div>` : ''}
                            ${app.note ? `<div class="field-row" style="grid-column: 1 / -1;"><span class="field-key">Cryptographic Note:</span><span class="field-val">${app.note}</span></div>` : ''}
                        </div>
                    </div>
                `;
            }

            elements.modalBody.innerHTML = html;
            elements.modal.style.display = "flex";
        } catch (err) {
            console.error("Packet detail modal error:", err);
        }
    }

    // Refresh All Data
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

    // 9. Event Listeners

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
            showNotification(`Upload error: ${err.message}`, "error", 6000);
        } finally {
            hideLoading();
            elements.pcapInput.value = "";
        }
    });

    // Load Sample PCAP
    elements.btnLoadSample.addEventListener("click", async () => {
        showLoading("Loading pre-generated multi-protocol sample PCAP...");
        elements.statusText.textContent = "Loading...";
        elements.statusDot.className = "status-dot status-running";

        try {
            const res = await fetch("/api/captures/load-sample", { method: "POST" });
            const data = await res.json();

            if (res.ok) {
                showNotification(`Loaded ${data.filename} (${data.summary.total_packets} packets) successfully.`, "info");
                elements.statusText.textContent = "Ready";
                elements.statusDot.className = "status-dot status-ready";
                elements.modeBadge.textContent = "Mode: Offline Sample";
                elements.sessionBadge.textContent = "sample_traffic.pcap";
                state.currentPage = 1;
                clearFlowFilter();
                await refreshAll();
            } else {
                showNotification(`Sample load failed: ${data.error}`, "error", 5000);
            }
        } catch (err) {
            showNotification(`Sample error: ${err.message}`, "error", 5000);
        } finally {
            hideLoading();
        }
    });

    // Open Threshold Config Modal
    elements.btnOpenConfig.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/alerts/config");
            const data = await res.json();
            const cfg = data.thresholds || {};

            elements.cfgSynFlood.value = cfg.syn_flood_threshold || 20;
            elements.cfgPortScan.value = cfg.port_scan_threshold || 15;
            elements.cfgPacketRate.value = cfg.packet_rate_threshold || 150;
            elements.cfgByteRate.value = cfg.byte_rate_threshold || 500000;
            elements.cfgHostRatio.value = cfg.host_volume_ratio || 0.5;
            elements.cfgCooldown.value = cfg.cooldown_seconds || 10;

            elements.configModal.style.display = "flex";
        } catch (err) {
            showNotification(`Failed to load thresholds: ${err.message}`, "error");
        }
    });

    elements.btnCloseConfig.addEventListener("click", () => { elements.configModal.style.display = "none"; });
    elements.btnCancelConfig.addEventListener("click", () => { elements.configModal.style.display = "none"; });

    elements.btnSaveConfig.addEventListener("click", async () => {
        const payload = {
            syn_flood_threshold: parseInt(elements.cfgSynFlood.value),
            port_scan_threshold: parseInt(elements.cfgPortScan.value),
            packet_rate_threshold: parseInt(elements.cfgPacketRate.value),
            byte_rate_threshold: parseInt(elements.cfgByteRate.value),
            host_volume_ratio: parseFloat(elements.cfgHostRatio.value),
            cooldown_seconds: parseInt(elements.cfgCooldown.value),
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
                showNotification(`Update failed: ${data.error}`, "error");
            }
        } catch (err) {
            showNotification(`Threshold save error: ${err.message}`, "error");
        }
    });

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

            if (res.ok && data.success) {
                state.isCapturing = true;
                elements.statusText.textContent = "Capturing";
                elements.statusDot.className = "status-dot status-running";
                elements.modeBadge.textContent = "Mode: Live Sniffing";
                elements.sessionBadge.textContent = `Iface: ${iface || 'Default'}`;
                elements.btnStartLive.style.display = "none";
                elements.btnStopLive.style.display = "inline-flex";

                showNotification("Live capture active. Polling metrics every 1.5s.", "info");
                state.livePollInterval = setInterval(refreshAll, 1500);
            } else {
                showNotification(`Live capture unavailable: ${data.error}`, "error", 7000);
            }
        } catch (err) {
            showNotification(`Live capture error: ${err.message}`, "error", 7000);
        }
    });

    // Stop Live Capture
    elements.btnStopLive.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/captures/stop", { method: "POST" });
            const data = await res.json();

            state.isCapturing = false;
            clearInterval(state.livePollInterval);
            elements.statusText.textContent = "Stopped";
            elements.statusDot.className = "status-dot status-ready";
            elements.btnStopLive.style.display = "none";
            elements.btnStartLive.style.display = "inline-flex";

            showNotification(`Live capture stopped. Captured ${data.packets_captured} packets.`, "info");
            await refreshAll();
        } catch (err) {
            console.error("Stop capture error:", err);
        }
    });

    // Manual Refresh
    elements.btnRefresh.addEventListener("click", () => {
        refreshAll();
        showNotification("Dashboard refreshed.", "info", 2000);
    });

    // Switch Protocol Layer Donut
    elements.protocolLayerSelect.addEventListener("change", (e) => {
        state.protocolLayer = e.target.value;
        refreshProtocols();
    });

    // Switch Timeline Metric
    elements.btnToggleTimeline.addEventListener("click", () => {
        state.timelineMetric = (state.timelineMetric === "pps") ? "kbps" : "pps";
        elements.btnToggleTimeline.textContent = `Switch Metric (${state.timelineMetric.toUpperCase()})`;
        refreshTimeline();
    });

    // Talkers Tab Switching
    document.querySelectorAll("#talker-tabs .tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("#talker-tabs .tab-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            state.talkerTab = btn.dataset.tab;
            refreshTalkersAndFlows();
        });
    });

    // Filters & Search
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
        }, 250);
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
        showNotification("All filters cleared.", "info", 1500);
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

    // Column Sorting
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

    // Modal Close
    elements.btnCloseModal.addEventListener("click", () => { elements.modal.style.display = "none"; });
    window.addEventListener("click", (e) => {
        if (e.target === elements.modal) elements.modal.style.display = "none";
        if (e.target === elements.configModal) elements.configModal.style.display = "none";
    });

    // Initial Load
    loadInterfaces();
    refreshAll();
});
