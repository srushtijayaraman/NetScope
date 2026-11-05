/**
 * NetScope X: Enterprise Architecture Upgrade Controller
 * Implements:
 * - 9-View Left Navigation Rail & View Orchestration
 * - Feature A: Interactive HTML5 Network Topology & Host Inspector
 * - Feature B & E: Security Incident Center & Explainable SOC Engine
 * - Feature C: Traffic Replay & Demonstration Lab Controller
 * - Feature F: Forensic Investigation Cases & Worklog
 * - Cross-view Deep Linking & Report Hub Integration
 */

document.addEventListener("DOMContentLoaded", () => {
    // =========================================================================
    // 1. VIEW ROUTER & NAVIGATION RAIL
    // =========================================================================
    const navItems = document.querySelectorAll(".nav-item[data-view]");
    const viewPanels = document.querySelectorAll(".view-panel");

    function switchView(viewName) {
        navItems.forEach(item => {
            if (item.getAttribute("data-view") === viewName) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        });

        viewPanels.forEach(panel => {
            if (panel.id === `view-${viewName}`) {
                panel.classList.add("active");
                panel.style.display = "block";
            } else {
                panel.classList.remove("active");
                panel.style.display = "none";
            }
        });

        // Trigger view-specific loads or resize adjustments
        if (viewName === "topology") {
            resizeTopologyCanvas();
            loadTopology();
        } else if (viewName === "incidents") {
            loadIncidents();
        } else if (viewName === "replay") {
            loadReplayStatus();
        } else if (viewName === "cases") {
            loadCases();
        } else if (viewName === "flows") {
            if (window.NetScope && window.NetScope.refreshFlows) window.NetScope.refreshFlows();
        } else if (viewName === "packets") {
            if (window.NetScope && window.NetScope.refreshPackets) window.NetScope.refreshPackets();
        }
    }

    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const view = item.getAttribute("data-view");
            if (view) switchView(view);
        });
    });

    // =========================================================================
    // 2. FEATURE A: INTERACTIVE NETWORK TOPOLOGY (HTML5 Canvas)
    // =========================================================================
    const topoCanvas = document.getElementById("topology-canvas");
    const topoContainer = document.getElementById("topo-container");
    const topoDrawer = document.getElementById("topo-drawer");
    const topoDrawerTitle = document.getElementById("topo-drawer-title");
    const topoDrawerRole = document.getElementById("topo-drawer-role");
    const topoDrawerBody = document.getElementById("topo-drawer-body");
    const btnCloseTopoDrawer = document.getElementById("btn-close-topo-drawer");
    const topoMinPackets = document.getElementById("topo-min-packets");
    const topoMinPacketsVal = document.getElementById("topo-min-packets-val");
    const topoProtoFilter = document.getElementById("topo-proto-filter");
    const topoSearchInput = document.getElementById("topo-search-input");
    const btnTopoResetZoom = document.getElementById("btn-topo-reset-zoom");
    const btnTopoRefresh = document.getElementById("btn-topo-refresh");
    const navNodesCount = document.getElementById("nav-nodes-count");
    const topoNodeCountBadge = document.getElementById("topo-node-count-badge");
    const topoEdgeCountBadge = document.getElementById("topo-edge-count-badge");

    let topoCtx = topoCanvas ? topoCanvas.getContext("2d") : null;
    let topoData = { nodes: [], edges: [], summary: {} };
    let topoNodesMap = new Map();
    let selectedNode = null;
    let hoveredNode = null;
    let topoAnimationId = null;

    // Viewport transform (pan & zoom)
    let panX = 0;
    let panY = 0;
    let zoomScale = 1.0;
    let isDragging = false;
    let dragStartX = 0;
    let dragStartY = 0;
    let pulseAngle = 0;

    function resizeTopologyCanvas() {
        if (!topoCanvas || !topoContainer) return;
        const rect = topoContainer.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        topoCanvas.width = rect.width * dpr;
        topoCanvas.height = rect.height * dpr;
        topoCanvas.style.width = `${rect.width}px`;
        topoCanvas.style.height = `${rect.height}px`;
        if (topoCtx) {
            topoCtx.setTransform(1, 0, 0, 1, 0, 0);
            topoCtx.scale(dpr, dpr);
        }
        if (panX === 0 && panY === 0) {
            panX = rect.width / 2;
            panY = rect.height / 2;
        }
    }

    window.addEventListener("resize", () => {
        if (document.getElementById("view-topology").classList.contains("active")) {
            resizeTopologyCanvas();
            renderTopology();
        }
    });

    async function loadTopology() {
        if (!topoCanvas) return;
        const minPkts = topoMinPackets ? topoMinPackets.value : 1;
        const proto = topoProtoFilter ? topoProtoFilter.value : "";
        const search = topoSearchInput ? topoSearchInput.value.trim() : "";

        try {
            const res = await fetch(`/api/topology?min_packets=${minPkts}&protocol=${encodeURIComponent(proto)}&search=${encodeURIComponent(search)}`);
            if (!res.ok) return;
            topoData = await res.json();

            if (navNodesCount) navNodesCount.textContent = `${topoData.nodes.length} Hosts`;
            if (topoNodeCountBadge) topoNodeCountBadge.textContent = `${topoData.nodes.length} Nodes`;
            if (topoEdgeCountBadge) topoEdgeCountBadge.textContent = `${topoData.edges.length} Edges`;

            layoutTopologyNodes();
            renderTopology();
        } catch (err) {
            console.error("Topology fetch error:", err);
        }
    }

    function layoutTopologyNodes() {
        topoNodesMap.clear();
        const nodes = topoData.nodes || [];
        if (nodes.length === 0) return;

        const internalNodes = nodes.filter(n => n.is_internal);
        const externalNodes = nodes.filter(n => !n.is_internal);

        const innerRadius = Math.max(90, Math.min(260, 40 + internalNodes.length * 28));
        const outerRadius = innerRadius + 140;

        // Position internal nodes along inner orbit
        internalNodes.forEach((node, i) => {
            const angle = (i / Math.max(1, internalNodes.length)) * 2 * Math.PI - Math.PI / 2;
            const x = Math.cos(angle) * innerRadius;
            const y = Math.sin(angle) * innerRadius;
            topoNodesMap.set(node.id, { ...node, x, y, radius: Math.min(32, Math.max(14, 12 + Math.log2(node.packet_count + 1) * 3)) });
        });

        // Position external nodes along outer orbit
        externalNodes.forEach((node, i) => {
            const angle = (i / Math.max(1, externalNodes.length)) * 2 * Math.PI - Math.PI / 2;
            const x = Math.cos(angle) * outerRadius;
            const y = Math.sin(angle) * outerRadius;
            topoNodesMap.set(node.id, { ...node, x, y, radius: Math.min(30, Math.max(12, 10 + Math.log2(node.packet_count + 1) * 3)) });
        });
    }

    function renderTopology() {
        if (!topoCtx || !topoCanvas) return;
        const rect = topoContainer.getBoundingClientRect();
        topoCtx.clearRect(0, 0, rect.width, rect.height);

        topoCtx.save();
        topoCtx.translate(panX, panY);
        topoCtx.scale(zoomScale, zoomScale);

        // Draw radial grid background
        topoCtx.strokeStyle = "rgba(100, 116, 139, 0.08)";
        topoCtx.lineWidth = 1;
        [100, 200, 320, 460].forEach(r => {
            topoCtx.beginPath();
            topoCtx.arc(0, 0, r, 0, 2 * Math.PI);
            topoCtx.stroke();
        });

        // Draw Communication Edges
        pulseAngle = (pulseAngle + 0.03) % (2 * Math.PI);
        (topoData.edges || []).forEach(edge => {
            const src = topoNodesMap.get(edge.source);
            const dst = topoNodesMap.get(edge.target);
            if (!src || !dst) return;

            const isHighIntensity = (edge.packet_count || 0) > 15;
            topoCtx.beginPath();
            topoCtx.moveTo(src.x, src.y);
            topoCtx.lineTo(dst.x, dst.y);

            let strokeColor = "rgba(56, 189, 248, 0.35)"; // TCP Blue default
            if ((edge.dominant_protocol || "").includes("UDP")) strokeColor = "rgba(52, 211, 153, 0.4)";
            if ((edge.dominant_protocol || "").includes("ICMP")) strokeColor = "rgba(192, 132, 252, 0.5)";

            topoCtx.strokeStyle = strokeColor;
            topoCtx.lineWidth = Math.min(6, Math.max(1.2, Math.log10(edge.packet_count + 1) * 2));
            topoCtx.stroke();

            // Traveling active packet pulse particle
            const t = (Math.sin(pulseAngle + (src.x % 5)) + 1) / 2;
            const px = src.x + (dst.x - src.x) * t;
            const py = src.y + (dst.y - src.y) * t;
            topoCtx.beginPath();
            topoCtx.arc(px, py, isHighIntensity ? 3.5 : 2.0, 0, 2 * Math.PI);
            topoCtx.fillStyle = "#38bdf8";
            topoCtx.fill();
        });

        // Draw Host Nodes
        topoNodesMap.forEach(node => {
            const hasAlerts = (node.alerts && node.alerts.length > 0) || node.risk_score > 0;
            const isSelected = selectedNode && selectedNode.id === node.id;
            const isHovered = hoveredNode && hoveredNode.id === node.id;

            // Halo for alerts or selection
            if (hasAlerts || isSelected) {
                topoCtx.beginPath();
                const glowR = node.radius + (hasAlerts ? 6 + Math.sin(pulseAngle * 2) * 3 : 5);
                topoCtx.arc(node.x, node.y, glowR, 0, 2 * Math.PI);
                topoCtx.fillStyle = hasAlerts ? "rgba(244, 63, 94, 0.25)" : "rgba(56, 189, 248, 0.25)";
                topoCtx.fill();
            }

            // Node Circle
            topoCtx.beginPath();
            topoCtx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);

            let fillColor = node.is_internal ? "#10b981" : "#6366f1";
            if (hasAlerts) fillColor = "#f43f5e";
            if (isSelected) fillColor = "#38bdf8";

            topoCtx.fillStyle = fillColor;
            topoCtx.fill();
            topoCtx.strokeStyle = isHovered ? "#ffffff" : "rgba(255, 255, 255, 0.4)";
            topoCtx.lineWidth = isHovered ? 2.5 : 1.5;
            topoCtx.stroke();

            // Label IP and Role
            topoCtx.font = "10px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
            topoCtx.fillStyle = "#f8fafc";
            topoCtx.textAlign = "center";
            topoCtx.fillText(node.label || node.id, node.x, node.y + node.radius + 13);

            if (node.packet_count > 0) {
                topoCtx.font = "9px monospace";
                topoCtx.fillStyle = "rgba(148, 163, 184, 0.9)";
                topoCtx.fillText(`${node.packet_count} pkts`, node.x, node.y + node.radius + 24);
            }
        });

        topoCtx.restore();
    }

    // Animation Loop for live flow particle streaming
    function startTopologyAnimation() {
        if (topoAnimationId) cancelAnimationFrame(topoAnimationId);
        function loop() {
            if (document.getElementById("view-topology").classList.contains("active")) {
                renderTopology();
            }
            topoAnimationId = requestAnimationFrame(loop);
        }
        topoAnimationId = requestAnimationFrame(loop);
    }
    startTopologyAnimation();

    // Canvas Mouse Events: Pan, Zoom & Selection
    if (topoCanvas) {
        topoCanvas.addEventListener("mousedown", (e) => {
            isDragging = true;
            dragStartX = e.clientX - panX;
            dragStartY = e.clientY - panY;
        });

        window.addEventListener("mouseup", () => {
            isDragging = false;
        });

        topoCanvas.addEventListener("mousemove", (e) => {
            const rect = topoContainer.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;

            if (isDragging) {
                panX = e.clientX - dragStartX;
                panY = e.clientY - dragStartY;
                return;
            }

            // Hit test for nodes
            const worldX = (mouseX - panX) / zoomScale;
            const worldY = (mouseY - panY) / zoomScale;

            let hit = null;
            topoNodesMap.forEach(node => {
                const dist = Math.hypot(worldX - node.x, worldY - node.y);
                if (dist <= node.radius + 4) hit = node;
            });

            hoveredNode = hit;
            topoCanvas.style.cursor = hit ? "pointer" : "grab";
        });

        topoCanvas.addEventListener("wheel", (e) => {
            e.preventDefault();
            const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
            const newScale = Math.min(3.5, Math.max(0.35, zoomScale * zoomFactor));

            const rect = topoContainer.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;

            panX = mouseX - (mouseX - panX) * (newScale / zoomScale);
            panY = mouseY - (mouseY - panY) * (newScale / zoomScale);
            zoomScale = newScale;
        }, { passive: false });

        topoCanvas.addEventListener("click", (e) => {
            const rect = topoContainer.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;
            const worldX = (mouseX - panX) / zoomScale;
            const worldY = (mouseY - panY) / zoomScale;

            let clickedNode = null;
            topoNodesMap.forEach(node => {
                const dist = Math.hypot(worldX - node.x, worldY - node.y);
                if (dist <= node.radius + 4) clickedNode = node;
            });

            selectedNode = clickedNode;
            if (clickedNode) {
                openNodeInspector(clickedNode);
            } else {
                if (topoDrawer) topoDrawer.style.display = "none";
            }
        });
    }

    if (btnTopoResetZoom) {
        btnTopoResetZoom.addEventListener("click", () => {
            const rect = topoContainer.getBoundingClientRect();
            panX = rect.width / 2;
            panY = rect.height / 2;
            zoomScale = 1.0;
        });
    }

    if (btnTopoRefresh) {
        btnTopoRefresh.addEventListener("click", loadTopology);
    }

    if (topoMinPackets) {
        topoMinPackets.addEventListener("input", (e) => {
            if (topoMinPacketsVal) topoMinPacketsVal.textContent = e.target.value;
            loadTopology();
        });
    }

    if (topoProtoFilter) {
        topoProtoFilter.addEventListener("change", loadTopology);
    }

    if (topoSearchInput) {
        let topoDebounce = null;
        topoSearchInput.addEventListener("input", () => {
            clearTimeout(topoDebounce);
            topoDebounce = setTimeout(loadTopology, 250);
        });
    }

    if (btnCloseTopoDrawer && topoDrawer) {
        btnCloseTopoDrawer.addEventListener("click", () => {
            topoDrawer.style.display = "none";
            selectedNode = null;
        });
    }

    function openNodeInspector(node) {
        if (!topoDrawer) return;
        topoDrawer.style.display = "flex";
        if (topoDrawerTitle) topoDrawerTitle.textContent = node.label || node.id;
        if (topoDrawerRole) {
            topoDrawerRole.textContent = node.role || (node.is_internal ? "Internal Endpoint" : "External Host");
            topoDrawerRole.className = `badge ${node.is_internal ? "badge-success" : "badge-academic"}`;
        }

        const alertsCount = (node.alerts || []).length;
        const peersList = (node.peers || []).map(p => `<span class="evidence-chip btn-jump-peer" data-ip="${p}">${p}</span>`).join(" ") || '<span class="text-muted">None</span>';
        const flowsList = (node.flows || []).map(f => `<span class="evidence-chip btn-jump-flow" data-flow="${f}">${f}</span>`).join(" ") || '<span class="text-muted">None</span>';

        topoDrawerBody.innerHTML = `
            <div class="kpi-card" style="border-left: 3px solid ${node.risk_score > 0 ? "var(--accent-rose)" : "var(--accent-emerald)"}; margin-bottom: 8px;">
                <div class="kpi-title">Risk Assessment</div>
                <div class="kpi-value" style="font-size:14px; font-weight:700;">
                    ${node.risk_score > 0 ? `<span style="color:var(--accent-rose);">SUSPICIOUS (${alertsCount} Heuristic Triggers)</span>` : `<span style="color:var(--accent-emerald);">NORMAL BEHAVIOR</span>`}
                </div>
            </div>

            <div class="incident-fact-box">
                <div class="field-row"><span class="field-key">Total Frames:</span><span class="field-val font-semibold">${node.packet_count} packets</span></div>
                <div class="field-row"><span class="field-key">Sent / Received:</span><span class="field-val">${node.sent_packets || 0} sent &bull; ${node.recv_packets || 0} recv</span></div>
                <div class="field-row"><span class="field-key">Volume (Bytes):</span><span class="field-val">${node.byte_count || 0} Bytes</span></div>
                <div class="field-row"><span class="field-key">Protocols Seen:</span><span class="field-val">${(node.protocols || []).join(", ") || "IP"}</span></div>
            </div>

            <div>
                <strong style="font-size:11px; text-transform:uppercase; color:var(--text-secondary);">Connected Host Peers</strong>
                <div style="margin-top: 6px; display:flex; flex-wrap:wrap; gap:4px;">${peersList}</div>
            </div>

            <div style="margin-top: 10px;">
                <strong style="font-size:11px; text-transform:uppercase; color:var(--text-secondary);">Active 5-Tuple Conversations</strong>
                <div style="margin-top: 6px; display:flex; flex-wrap:wrap; gap:4px;">${flowsList}</div>
            </div>

            <div style="margin-top: 14px; display:flex; flex-direction:column; gap:8px;">
                <button class="btn btn-outline btn-sm btn-block" id="btn-topo-filter-packets" data-ip="${node.id}">
                    Filter Packet Explorer to this Host
                </button>
                <button class="btn btn-primary btn-sm btn-block" id="btn-topo-create-case" data-ip="${node.id}">
                    Create Investigation Case
                </button>
            </div>
        `;

        // Bind Drawer Action Buttons
        document.getElementById("btn-topo-filter-packets")?.addEventListener("click", () => {
            switchView("packets");
            const filterInput = document.getElementById("filter-search");
            if (filterInput) {
                filterInput.value = node.id;
                filterInput.dispatchEvent(new Event("input"));
            }
        });

        document.getElementById("btn-topo-create-case")?.addEventListener("click", () => {
            openNewCaseModal(`Investigation: Host ${node.id} Traffic Activity`, `Forensic analysis of communication patterns for host ${node.id}`);
        });

        // Click on peer jumps or highlights
        topoDrawerBody.querySelectorAll(".btn-jump-peer").forEach(el => {
            el.addEventListener("click", (e) => {
                const peerIp = e.target.dataset.ip;
                const peerNode = topoNodesMap.get(peerIp);
                if (peerNode) {
                    selectedNode = peerNode;
                    panX = (topoContainer.getBoundingClientRect().width / 2) - peerNode.x * zoomScale;
                    panY = (topoContainer.getBoundingClientRect().height / 2) - peerNode.y * zoomScale;
                    openNodeInspector(peerNode);
                }
            });
        });

        // Click on flow opens timeline modal
        topoDrawerBody.querySelectorAll(".btn-jump-flow").forEach(el => {
            el.addEventListener("click", (e) => {
                const fid = e.target.dataset.flow;
                if (fid && window.NetScope && window.NetScope.openFlowTimeline) {
                    window.NetScope.openFlowTimeline(fid);
                }
            });
        });
    }

    // =========================================================================
    // 3. FEATURE B & E: SECURITY INCIDENT CENTER & EXPLAINABLE SOC ENGINE
    // =========================================================================
    const incidentContainer = document.getElementById("incidents-cards-container");
    const incidentDrawer = document.getElementById("incident-drawer");
    const incDrawerTitle = document.getElementById("inc-drawer-title");
    const incDrawerSeverity = document.getElementById("inc-drawer-severity");
    const incDrawerStatus = document.getElementById("inc-drawer-status");
    const incDrawerBody = document.getElementById("inc-drawer-body");
    const btnCloseIncDrawer = document.getElementById("btn-close-inc-drawer");
    const btnRefreshIncidents = document.getElementById("btn-refresh-incidents");
    const incidentSeveritySelect = document.getElementById("incident-severity-select");
    const navIncidentBadge = document.getElementById("nav-incident-badge");

    let currentIncidents = [];
    let selectedIncident = null;
    let incidentStatusFilter = "";

    // Status filter tabs
    document.querySelectorAll("#incident-status-tabs .tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("#incident-status-tabs .tab-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            incidentStatusFilter = btn.dataset.status || "";
            loadIncidents();
        });
    });

    if (incidentSeveritySelect) {
        incidentSeveritySelect.addEventListener("change", loadIncidents);
    }

    if (btnRefreshIncidents) {
        btnRefreshIncidents.addEventListener("click", loadIncidents);
    }

    if (btnCloseIncDrawer && incidentDrawer) {
        btnCloseIncDrawer.addEventListener("click", () => {
            incidentDrawer.style.display = "none";
            selectedIncident = null;
        });
    }

    async function loadIncidents() {
        if (!incidentContainer) return;
        const sev = incidentSeveritySelect ? incidentSeveritySelect.value : "";
        const params = new URLSearchParams();
        if (incidentStatusFilter) params.append("status", incidentStatusFilter);
        if (sev) params.append("severity", sev);

        try {
            const res = await fetch(`/api/incidents?${params.toString()}`);
            if (!res.ok) return;
            const data = await res.json();
            currentIncidents = data.incidents || [];

            if (navIncidentBadge) {
                navIncidentBadge.textContent = currentIncidents.length;
                navIncidentBadge.className = currentIncidents.length > 0 ? "nav-pill nav-pill-warning" : "nav-pill";
            }

            renderIncidentList();
        } catch (err) {
            console.error("Incidents fetch error:", err);
        }
    }

    function renderIncidentList() {
        if (!incidentContainer) return;
        if (currentIncidents.length === 0) {
            incidentContainer.innerHTML = `
                <div class="empty-state">
                    No security incidents matching current filters. Run a Replay scenario or load sample traffic.
                </div>
            `;
            return;
        }

        incidentContainer.innerHTML = "";
        currentIncidents.forEach(inc => {
            const card = document.createElement("div");
            const sevClass = (inc.severity || "HIGH").toLowerCase();
            card.className = `incident-card sev-${sevClass} ${selectedIncident && selectedIncident.incident_id === inc.incident_id ? "active" : ""}`;
            card.dataset.id = inc.incident_id;

            card.innerHTML = `
                <div class="inc-card-header">
                    <span class="inc-card-title">${inc.title || "Security Incident"}</span>
                    <div style="display:flex; gap:6px;">
                        <span class="badge ${inc.severity === 'HIGH' ? 'badge-danger' : 'badge-warning'}">${inc.severity}</span>
                        <span class="badge ${inc.status === 'Resolved' ? 'badge-success' : 'badge-soc'}">${inc.status || 'New'}</span>
                    </div>
                </div>
                <div class="inc-card-meta">
                    <span><strong>Target:</strong> ${inc.target_host || 'Network Gateway'}</span>
                    <span><strong>Rule:</strong> ${inc.rule_triggered || 'Heuristic Anomaly'}</span>
                    <span><strong>Evidence:</strong> ${(inc.evidence_packets || []).length} frames</span>
                    <span><strong>Last Seen:</strong> ${inc.last_seen || '-'}</span>
                </div>
            `;

            card.addEventListener("click", () => {
                document.querySelectorAll(".incident-card").forEach(c => c.classList.remove("active"));
                card.classList.add("active");
                selectedIncident = inc;
                openIncidentDrawer(inc);
            });

            incidentContainer.appendChild(card);
        });
    }

    function openIncidentDrawer(inc) {
        if (!incidentDrawer) return;
        incidentDrawer.style.display = "flex";
        if (incDrawerTitle) incDrawerTitle.textContent = inc.title || `Incident ${inc.incident_id}`;
        if (incDrawerSeverity) {
            incDrawerSeverity.textContent = inc.severity || "HIGH";
            incDrawerSeverity.className = `badge ${inc.severity === 'HIGH' ? 'badge-danger' : 'badge-warning'}`;
        }
        if (incDrawerStatus) {
            incDrawerStatus.textContent = inc.status || "New";
            incDrawerStatus.className = `badge ${inc.status === 'Resolved' ? 'badge-success' : 'badge-soc'}`;
        }

        const evidencePackets = (inc.evidence_packets || []).map(pid => 
            `<button class="evidence-chip btn-inspect-pkt" data-id="${pid}">#Pkt ${pid}</button>`
        ).join(" ") || '<span class="text-muted">None attached</span>';

        const relatedFlows = (inc.related_flows || []).map(fid => 
            `<button class="evidence-chip btn-inspect-flow" data-id="${fid}">${fid}</button>`
        ).join(" ") || '<span class="text-muted">None attached</span>';

        const analystNotesList = (inc.analyst_notes || []).map(n => 
            `<div style="font-size:11px; padding:6px 8px; background:var(--bg-surface); border-radius:4px; margin-bottom:4px; border:1px solid var(--border-subtle);">${n}</div>`
        ).join("") || '<span class="text-muted" style="font-size:11px;">No analyst notes entered.</span>';

        incDrawerBody.innerHTML = `
            <!-- Status Update Controller -->
            <div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-surface); padding:8px 12px; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);">
                <span class="field-key">Workflow Status:</span>
                <select id="inc-status-select" class="form-select-sm">
                    <option value="New" ${inc.status === 'New' ? 'selected' : ''}>New</option>
                    <option value="Investigating" ${inc.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
                    <option value="Resolved" ${inc.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                </select>
            </div>

            <!-- Threat Assessment Summary -->
            <div class="incident-fact-box">
                <div class="field-row"><span class="field-key">Incident ID:</span><span class="field-val font-semibold">${inc.incident_id}</span></div>
                <div class="field-row"><span class="field-key">Detection Engine:</span><span class="field-val">${inc.rule_triggered}</span></div>
                <div class="field-row"><span class="field-key">Target Entity:</span><span class="field-val">${inc.target_host}</span></div>
                <div class="field-row"><span class="field-key">Confidence Score:</span><span class="field-val">${Math.round((inc.confidence || 0.85) * 100)}%</span></div>
            </div>

            <!-- Feature E: Explainable Detection Engine -->
            <div>
                <strong style="font-size:11px; text-transform:uppercase; color:var(--accent-blue);">Observable Facts (Deterministic)</strong>
                <div class="incident-fact-box" style="margin-top:4px; border-left:3px solid var(--accent-blue);">
                    ${inc.facts || 'Direct network telemetry: Rapid consecutive SYN flags without corresponding handshake ACK tokens.'}
                </div>
            </div>

            <div>
                <strong style="font-size:11px; text-transform:uppercase; color:var(--accent-rose);">Security Hypothesis</strong>
                <div class="incident-fact-box" style="margin-top:4px; border-left:3px solid var(--accent-rose);">
                    ${inc.hypothesis || 'Host is engaging in unauthorized port enumeration reconnaissance or resource exhaustion DoS.'}
                </div>
            </div>

            <div>
                <strong style="font-size:11px; text-transform:uppercase; color:var(--accent-emerald);">Alternative Benign Explanations</strong>
                <div class="incident-fact-box" style="margin-top:4px; border-left:3px solid var(--accent-emerald);">
                    ${inc.benign_explanations || 'Scheduled vulnerability scan by internal SecOps, corporate proxy health check, or backup pipeline.'}
                </div>
            </div>

            <!-- Forensic Evidence Anchors -->
            <div>
                <strong style="font-size:11px; text-transform:uppercase; color:var(--text-secondary);">Evidence Packets (Click to Inspect)</strong>
                <div style="margin-top:6px; display:flex; flex-wrap:wrap; gap:4px;">${evidencePackets}</div>
            </div>

            <div>
                <strong style="font-size:11px; text-transform:uppercase; color:var(--text-secondary);">Associated Network Conversations</strong>
                <div style="margin-top:6px; display:flex; flex-wrap:wrap; gap:4px;">${relatedFlows}</div>
            </div>

            <!-- Analyst Notes Timeline -->
            <div>
                <strong style="font-size:11px; text-transform:uppercase; color:var(--text-secondary);">Analyst Notes & Findings</strong>
                <div id="inc-notes-history" style="margin-top:6px; max-height:120px; overflow-y:auto;">
                    ${analystNotesList}
                </div>
                <div style="display:flex; gap:6px; margin-top:8px;">
                    <input type="text" id="inc-note-input" class="form-input form-input-sm" placeholder="Enter forensic note...">
                    <button class="btn btn-outline btn-sm" id="btn-save-inc-note">Add</button>
                </div>
            </div>

            <!-- Actions -->
            <div style="margin-top:12px; display:flex; gap:8px;">
                <button class="btn btn-primary btn-sm btn-block" id="btn-escalate-case">
                    Escalate to Forensic Case
                </button>
            </div>
        `;

        // Status Changer Listener
        document.getElementById("inc-status-select")?.addEventListener("change", async (e) => {
            const newStatus = e.target.value;
            try {
                const res = await fetch(`/api/incidents/${inc.incident_id}`, {
                    method: "PATCH",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ status: newStatus })
                });
                if (res.ok) {
                    inc.status = newStatus;
                    incDrawerStatus.textContent = newStatus;
                    incDrawerStatus.className = `badge ${newStatus === 'Resolved' ? 'badge-success' : 'badge-soc'}`;
                    loadIncidents();
                }
            } catch (err) {
                console.error("Status update error:", err);
            }
        });

        // Add Analyst Note
        document.getElementById("btn-save-inc-note")?.addEventListener("click", async () => {
            const noteInput = document.getElementById("inc-note-input");
            const noteText = noteInput ? noteInput.value.trim() : "";
            if (!noteText) return;

            try {
                const res = await fetch(`/api/incidents/${inc.incident_id}`, {
                    method: "PATCH",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ analyst_notes: noteText })
                });
                if (res.ok) {
                    if (!inc.analyst_notes) inc.analyst_notes = [];
                    inc.analyst_notes.push(noteText);
                    noteInput.value = "";
                    openIncidentDrawer(inc);
                }
            } catch (err) {
                console.error("Add note error:", err);
            }
        });

        // Click on evidence packet opens Packet Inspector modal
        incDrawerBody.querySelectorAll(".btn-inspect-pkt").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const pid = parseInt(e.target.dataset.id);
                if (pid && window.NetScope && window.NetScope.showPacketModal) {
                    window.NetScope.showPacketModal(pid);
                }
            });
        });

        // Click on related flow opens conversation ladder
        incDrawerBody.querySelectorAll(".btn-inspect-flow").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const fid = e.target.dataset.id;
                if (fid && window.NetScope && window.NetScope.openFlowTimeline) {
                    window.NetScope.openFlowTimeline(fid);
                }
            });
        });

        // Escalate to Case
        document.getElementById("btn-escalate-case")?.addEventListener("click", () => {
            openNewCaseModal(`Case: ${inc.title || inc.incident_id}`, `Escalated security incident ${inc.incident_id} involving ${inc.target_host}`, inc.incident_id);
        });
    }

    // =========================================================================
    // 4. FEATURE C: TRAFFIC REPLAY & DEMONSTRATION LAB
    // =========================================================================
    const replayProgressBar = document.getElementById("replay-progress-bar");
    const replayScenarioName = document.getElementById("replay-scenario-name");
    const replayStateBadge = document.getElementById("replay-state-badge");
    const replayPktCounter = document.getElementById("replay-pkt-counter");
    const replayElapsedTime = document.getElementById("replay-elapsed-time");
    const replayEventsFeed = document.getElementById("replay-events-feed");
    const btnReplayPause = document.getElementById("btn-replay-pause");
    const btnReplayResume = document.getElementById("btn-replay-resume");
    const btnReplayStop = document.getElementById("btn-replay-stop");
    const btnReplayReset = document.getElementById("btn-replay-reset");

    let replaySpeed = 2.0;
    let replayPollTimer = null;
    let knownRuleHitsCount = 0;

    // Speed selector buttons
    document.querySelectorAll(".speed-selector .btn-speed").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".speed-selector .btn-speed").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            replaySpeed = parseFloat(btn.dataset.speed);
        });
    });

    // Start Scenario buttons
    document.querySelectorAll(".btn-start-scenario").forEach(btn => {
        btn.addEventListener("click", () => {
            const scId = btn.dataset.scenario;
            if (scId) startReplayScenario(scId);
        });
    });

    async function startReplayScenario(scenarioId) {
        try {
            knownRuleHitsCount = 0;
            if (replayEventsFeed) {
                replayEventsFeed.innerHTML = '<div class="replay-event-item" style="border-left-color:var(--accent-blue);">Scenario playback initiated...</div>';
            }

            const res = await fetch("/api/replay/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scenario_id: scenarioId, speed: replaySpeed })
            });

            if (!res.ok) {
                const err = await res.json();
                if (window.NetScope && window.NetScope.showNotification) {
                    window.NetScope.showNotification(`Replay start failed: ${err.error}`, "error");
                }
                return;
            }

            const data = await res.json();
            updateReplayUI(data.status);
            startReplayPolling();

            if (window.NetScope && window.NetScope.showNotification) {
                window.NetScope.showNotification(`Replay scenario "${scenarioId}" started.`, "info", 2000);
            }
        } catch (err) {
            console.error("Replay start error:", err);
        }
    }

    function startReplayPolling() {
        if (replayPollTimer) clearInterval(replayPollTimer);
        replayPollTimer = setInterval(async () => {
            const status = await loadReplayStatus();
            if (status && (status.state === "COMPLETED" || status.state === "STOPPED" || status.state === "IDLE")) {
                clearInterval(replayPollTimer);
                replayPollTimer = null;
                // Final full dashboard sync
                if (window.NetScope && window.NetScope.refreshAll) window.NetScope.refreshAll();
                loadIncidents();
            }
        }, 250);
    }

    async function loadReplayStatus() {
        try {
            const res = await fetch("/api/replay/status");
            if (!res.ok) return null;
            const status = await res.json();
            updateReplayUI(status);

            // Dynamically refresh overview metrics in background while streaming
            if (status.state === "RUNNING") {
                if (window.NetScope && window.NetScope.refreshAll) window.NetScope.refreshAll();
                loadIncidents();
            }
            return status;
        } catch (err) {
            console.error("Replay status error:", err);
            return null;
        }
    }

    function updateReplayUI(status) {
        if (!status) return;

        if (replayProgressBar) {
            replayProgressBar.style.width = `${status.progress_pct || 0}%`;
        }
        if (replayScenarioName) {
            replayScenarioName.textContent = status.scenario_name || status.scenario_id || "None";
        }
        if (replayStateBadge) {
            replayStateBadge.textContent = status.state || "IDLE";
            replayStateBadge.className = status.state === "RUNNING" ? "badge badge-success" : (status.state === "COMPLETED" ? "badge badge-soc" : "badge");
        }
        if (replayPktCounter) {
            replayPktCounter.textContent = `${status.current_packet || 0} / ${status.total_packets || 0} packets`;
        }
        if (replayElapsedTime) {
            replayElapsedTime.textContent = `${(status.elapsed_seconds || 0).toFixed(2)}s elapsed`;
        }

        // Check for new rule hits and append to live detection feed
        const hits = status.rule_hits || [];
        if (hits.length > knownRuleHitsCount && replayEventsFeed) {
            for (let i = knownRuleHitsCount; i < hits.length; i++) {
                const item = document.createElement("div");
                item.className = "replay-event-item";
                item.innerHTML = `
                    <span class="status-dot status-error" style="width:8px; height:8px;"></span>
                    <strong style="color:var(--accent-rose);">Anomaly Detected:</strong> ${hits[i]}
                `;
                replayEventsFeed.prepend(item);
            }
            knownRuleHitsCount = hits.length;
        }
    }

    // Player Controls
    btnReplayPause?.addEventListener("click", async () => {
        const res = await fetch("/api/replay/pause", { method: "POST" });
        if (res.ok) updateReplayUI((await res.json()).status);
    });

    btnReplayResume?.addEventListener("click", async () => {
        const res = await fetch("/api/replay/resume", { method: "POST" });
        if (res.ok) {
            updateReplayUI((await res.json()).status);
            startReplayPolling();
        }
    });

    btnReplayStop?.addEventListener("click", async () => {
        const res = await fetch("/api/replay/stop", { method: "POST" });
        if (res.ok) updateReplayUI((await res.json()).status);
    });

    btnReplayReset?.addEventListener("click", async () => {
        const res = await fetch("/api/replay/reset", { method: "POST" });
        if (res.ok) {
            updateReplayUI((await res.json()).status);
            if (replayEventsFeed) replayEventsFeed.innerHTML = '<div class="empty-state">Replay lab reset to idle state.</div>';
            if (window.NetScope && window.NetScope.refreshAll) window.NetScope.refreshAll();
            loadIncidents();
        }
    });

    // =========================================================================
    // 5. FEATURE F: FORENSIC INVESTIGATION CASES & REPORT GENERATOR
    // =========================================================================
    const casesTbody = document.getElementById("cases-tbody");
    const caseDrawer = document.getElementById("case-drawer");
    const caseDrawerTitle = document.getElementById("case-drawer-title");
    const caseDrawerStatus = document.getElementById("case-drawer-status");
    const caseDrawerBody = document.getElementById("case-drawer-body");
    const btnCloseCaseDrawer = document.getElementById("btn-close-case-drawer");
    const btnOpenNewCaseModal = document.getElementById("btn-open-new-case-modal");
    const modalNewCase = document.getElementById("modal-new-case");
    const btnCloseNewCaseModal = document.getElementById("btn-close-new-case-modal");
    const btnCancelNewCase = document.getElementById("btn-cancel-new-case");
    const formNewCase = document.getElementById("form-new-case");
    const navCaseBadge = document.getElementById("nav-case-badge");

    let currentCases = [];
    let selectedCase = null;

    async function loadCases() {
        if (!casesTbody) return;
        try {
            const res = await fetch("/api/cases");
            if (!res.ok) return;
            const data = await res.json();
            currentCases = data.cases || [];

            if (navCaseBadge) navCaseBadge.textContent = currentCases.length;
            renderCasesTable();
        } catch (err) {
            console.error("Cases fetch error:", err);
        }
    }

    function renderCasesTable() {
        if (!casesTbody) return;
        if (currentCases.length === 0) {
            casesTbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">No investigation cases open. Click "Create New Case" to start.</td></tr>';
            return;
        }

        casesTbody.innerHTML = "";
        currentCases.forEach(c => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="mono font-semibold">${c.case_id}</td>
                <td><strong>${c.title}</strong></td>
                <td><span class="badge ${c.priority === 'Critical' ? 'badge-danger' : (c.priority === 'High' ? 'badge-warning' : 'badge')}">${c.priority}</span></td>
                <td><span class="badge ${c.status === 'Closed' ? 'badge-success' : 'badge-soc'}">${c.status}</span></td>
                <td>${c.analyst || 'SecOps Lead'}</td>
                <td><span class="badge">${(c.artifacts || []).length} items</span></td>
                <td>${(c.notes || []).length} notes</td>
                <td class="text-muted" style="font-size:11px;">${c.created_at ? c.created_at.substr(0, 16) : '-'}</td>
                <td>
                    <button class="btn btn-outline btn-xs btn-open-case" data-id="${c.case_id}">Inspect</button>
                    <a href="/api/cases/${c.case_id}/report?download=1" class="btn btn-outline btn-xs" target="_blank" title="Export Standalone HTML Report">Report</a>
                </td>
            `;

            tr.querySelector(".btn-open-case")?.addEventListener("click", () => {
                selectedCase = c;
                openCaseDrawer(c);
            });

            casesTbody.appendChild(tr);
        });
    }

    function openCaseDrawer(c) {
        if (!caseDrawer) return;
        caseDrawer.style.display = "flex";
        if (caseDrawerTitle) caseDrawerTitle.textContent = `${c.case_id}: ${c.title}`;
        if (caseDrawerStatus) {
            caseDrawerStatus.textContent = c.status || "Open";
            caseDrawerStatus.className = `badge ${c.status === 'Closed' ? 'badge-success' : 'badge-soc'}`;
        }

        const artifactsList = (c.artifacts || []).map(a => 
            `<div class="incident-fact-box" style="margin-bottom:4px; font-size:11px;">
                <strong>${a.artifact_type.toUpperCase()}:</strong> ${a.artifact_id}
            </div>`
        ).join("") || '<span class="text-muted" style="font-size:11px;">No evidence artifacts attached.</span>';

        const notesTimeline = (c.notes || []).map(n => 
            `<div style="font-size:11px; padding:6px 8px; background:var(--bg-surface); border-radius:4px; margin-bottom:4px; border:1px solid var(--border-subtle);">
                <div style="display:flex; justify-content:space-between; color:var(--text-muted); font-size:10px; margin-bottom:2px;">
                    <span>${n.author || 'Analyst'}</span>
                    <span>${n.timestamp || ''}</span>
                </div>
                <div>${n.note}</div>
            </div>`
        ).join("") || '<span class="text-muted" style="font-size:11px;">No chronological notes recorded.</span>';

        caseDrawerBody.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-surface); padding:8px 12px; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);">
                <span class="field-key">Investigation State:</span>
                <select id="case-status-select" class="form-select-sm">
                    <option value="Open" ${c.status === 'Open' ? 'selected' : ''}>Open</option>
                    <option value="In Progress" ${c.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                    <option value="Closed" ${c.status === 'Closed' ? 'selected' : ''}>Closed</option>
                </select>
            </div>

            <div class="incident-fact-box">
                <div class="field-row"><span class="field-key">Priority:</span><span class="field-val font-semibold">${c.priority}</span></div>
                <div class="field-row"><span class="field-key">Assigned Analyst:</span><span class="field-val">${c.analyst}</span></div>
                <div class="field-row"><span class="field-key">Summary:</span><span class="field-val">${c.summary || 'No summary text.'}</span></div>
            </div>

            <div>
                <strong style="font-size:11px; text-transform:uppercase; color:var(--text-secondary);">Attached Forensic Artifacts</strong>
                <div style="margin-top:6px;">${artifactsList}</div>
            </div>

            <div>
                <strong style="font-size:11px; text-transform:uppercase; color:var(--text-secondary);">Analyst Investigation Log</strong>
                <div id="case-notes-container" style="margin-top:6px; max-height:160px; overflow-y:auto;">
                    ${notesTimeline}
                </div>
                <div style="display:flex; gap:6px; margin-top:8px;">
                    <input type="text" id="case-note-input" class="form-input form-input-sm" placeholder="Enter findings note...">
                    <button class="btn btn-outline btn-sm" id="btn-add-case-note">Add</button>
                </div>
            </div>

            <div style="margin-top:16px;">
                <a href="/api/cases/${c.case_id}/report?download=1" class="btn btn-primary btn-sm btn-block" target="_blank">
                    Export Standalone Forensic Report (HTML)
                </a>
            </div>
        `;

        // Case Status Selector Listener
        document.getElementById("case-status-select")?.addEventListener("change", async (e) => {
            const newStatus = e.target.value;
            try {
                const res = await fetch(`/api/cases/${c.case_id}`, {
                    method: "PATCH",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ status: newStatus })
                });
                if (res.ok) {
                    c.status = newStatus;
                    caseDrawerStatus.textContent = newStatus;
                    caseDrawerStatus.className = `badge ${newStatus === 'Closed' ? 'badge-success' : 'badge-soc'}`;
                    loadCases();
                }
            } catch (err) {
                console.error("Case status update error:", err);
            }
        });

        // Add Case Note Listener
        document.getElementById("btn-add-case-note")?.addEventListener("click", async () => {
            const noteInput = document.getElementById("case-note-input");
            const note = noteInput ? noteInput.value.trim() : "";
            if (!note) return;

            try {
                const res = await fetch(`/api/cases/${c.case_id}/notes`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ note, author: c.analyst || "SecOps Analyst" })
                });
                if (res.ok) {
                    const data = await res.json();
                    if (!c.notes) c.notes = [];
                    c.notes.push(data.note);
                    noteInput.value = "";
                    openCaseDrawer(c);
                }
            } catch (err) {
                console.error("Add case note error:", err);
            }
        });
    }

    if (btnCloseCaseDrawer && caseDrawer) {
        btnCloseCaseDrawer.addEventListener("click", () => {
            caseDrawer.style.display = "none";
            selectedCase = null;
        });
    }

    function openNewCaseModal(defaultTitle = "", defaultSummary = "", attachIncidentId = null) {
        if (!modalNewCase) return;
        const titleInput = document.getElementById("case-input-title");
        const summaryInput = document.getElementById("case-input-summary");
        if (titleInput) titleInput.value = defaultTitle;
        if (summaryInput) summaryInput.value = defaultSummary;
        modalNewCase.dataset.attachIncident = attachIncidentId || "";
        modalNewCase.style.display = "flex";
    }

    btnOpenNewCaseModal?.addEventListener("click", () => openNewCaseModal());
    btnCloseNewCaseModal?.addEventListener("click", () => { modalNewCase.style.display = "none"; });
    btnCancelNewCase?.addEventListener("click", () => { modalNewCase.style.display = "none"; });

    formNewCase?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const title = document.getElementById("case-input-title")?.value.trim();
        const summary = document.getElementById("case-input-summary")?.value.trim();
        const priority = document.getElementById("case-input-priority")?.value;
        const analyst = document.getElementById("case-input-analyst")?.value.trim();
        const note = document.getElementById("case-input-note")?.value.trim();
        const attachIncident = modalNewCase.dataset.attachIncident;

        const artifacts = [];
        if (attachIncident) {
            artifacts.push({ artifact_type: "incident", artifact_id: attachIncident });
        }

        try {
            const res = await fetch("/api/cases", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title,
                    summary,
                    priority,
                    analyst,
                    initial_note: note,
                    artifacts
                })
            });

            if (res.ok) {
                const data = await res.json();
                modalNewCase.style.display = "none";
                formNewCase.reset();
                switchView("cases");
                await loadCases();
                if (data.case) openCaseDrawer(data.case);
                if (window.NetScope && window.NetScope.showNotification) {
                    window.NetScope.showNotification("New forensic case registered successfully.", "info");
                }
            }
        } catch (err) {
            console.error("Create case error:", err);
        }
    });

    // =========================================================================
    // 6. REPORTS HUB & DIFFERENTIAL COMPARATOR
    // =========================================================================
    document.getElementById("btn-reports-download-session")?.addEventListener("click", () => {
        window.open("/api/export/report", "_blank");
    });

    document.getElementById("btn-reports-open-comparator")?.addEventListener("click", () => {
        if (window.NetScope && window.NetScope.openCompareModal) {
            window.NetScope.openCompareModal();
        }
    });

    // Initial fetch of NetScope X telemetry
    loadIncidents();
    loadCases();
    loadReplayStatus();
});
