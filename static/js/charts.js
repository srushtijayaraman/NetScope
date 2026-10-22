/**
 * NetScope Plotly Chart Rendering Engine
 * Quietly Technical Design System: Muted Teal, Slate Neutrals, and Precision Typography
 */

const NetScopeCharts = (() => {
    let currentTheme = "dark";
    let lastProtocolsData = null;
    let lastSelectedLayer = "transport";
    let lastTimelineData = null;
    let lastTimelineMetric = "pps";

    const fontStack = 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

    const themes = {
        dark: {
            paper_bgcolor: "transparent",
            plot_bgcolor: "transparent",
            font: { family: fontStack, color: "#95A3A0", size: 11 },
            gridcolor: "#242D2B",
            zerolinecolor: "#313D3A",
            donutTextColor: "#EAEFEC",
            ppsLine: "#2DD4BF",
            ppsFill: "rgba(45, 212, 191, 0.12)",
            kbpsLine: "#38BDF8",
            kbpsFill: "rgba(56, 189, 248, 0.12)",
            donutBorder: "#1B201F",
        },
        light: {
            paper_bgcolor: "transparent",
            plot_bgcolor: "transparent",
            font: { family: fontStack, color: "#616A67", size: 11 },
            gridcolor: "#E8E5DF",
            zerolinecolor: "#DAD6CD",
            donutTextColor: "#191C1B",
            ppsLine: "#0D9488",
            ppsFill: "rgba(13, 148, 136, 0.10)",
            kbpsLine: "#0284C7",
            kbpsFill: "rgba(2, 132, 199, 0.10)",
            donutBorder: "#FFFFFF",
        },
    };

    const protocolColors = {
        TCP: "#0EA5E9",
        UDP: "#8B5CF6",
        ICMP: "#F59E0B",
        ICMPv6: "#D97706",
        ARP: "#10B981",
        DNS: "#F43F5E",
        HTTP: "#0D9488",
        TLS: "#6366F1",
        IPv4: "#2DD4BF",
        IPv6: "#A78BFA",
        Other: "#64748B",
        Unknown: "#94A3B8",
    };

    function getThemeCfg() {
        return themes[currentTheme] || themes.dark;
    }

    function setTheme(newTheme) {
        if (newTheme !== "light" && newTheme !== "dark") return;
        currentTheme = newTheme;

        // Re-render currently displayed charts with the new theme
        if (lastProtocolsData) {
            renderProtocolChart(lastProtocolsData, lastSelectedLayer);
        }
        if (lastTimelineData) {
            renderTimelineChart(lastTimelineData, lastTimelineMetric);
        }
    }

    function renderProtocolChart(protocolsData, selectedLayer = "transport") {
        lastProtocolsData = protocolsData;
        lastSelectedLayer = selectedLayer;

        const container = document.getElementById("chart-protocols");
        const tableContainer = document.getElementById("protocol-legend-table");
        if (!container) return;

        const layerData = (protocolsData && protocolsData[selectedLayer]) || {};
        const labels = Object.keys(layerData);
        const counts = labels.map(l => layerData[l].count);
        const percentages = labels.map(l => layerData[l].percentage);
        const colors = labels.map(l => protocolColors[l] || "#64748B");

        if (labels.length === 0 || counts.reduce((a, b) => a + b, 0) === 0) {
            Plotly.purge(container);
            container.innerHTML = '<div class="empty-state-notice">No protocol records found for this layer.</div>';
            if (tableContainer) tableContainer.innerHTML = "";
            return;
        }

        const t = getThemeCfg();

        const plotData = [{
            labels: labels,
            values: counts,
            type: "pie",
            hole: 0.62,
            marker: { colors: colors, line: { color: t.donutBorder, width: 2 } },
            textinfo: "label+percent",
            hoverinfo: "label+value+percent",
            textposition: "inside",
            showlegend: false,
        }];

        const layout = {
            paper_bgcolor: t.paper_bgcolor,
            plot_bgcolor: t.plot_bgcolor,
            font: t.font,
            margin: { l: 15, r: 15, t: 15, b: 15 },
            annotations: [{
                font: { size: 11, color: t.donutTextColor, family: t.font.family, weight: "600" },
                showarrow: false,
                text: selectedLayer.toUpperCase(),
                x: 0.5,
                y: 0.5,
            }],
        };

        const config = { responsive: true, displayModeBar: false };
        Plotly.react(container, plotData, layout, config);

        // Update mini summary table with progress tracks
        if (tableContainer) {
            let html = '<div class="protocol-rank-list">';
            labels.forEach((lbl, idx) => {
                const color = colors[idx];
                const pct = percentages[idx].toFixed(1);
                html += `
                <div class="protocol-rank-row">
                    <div class="protocol-rank-meta">
                        <span class="protocol-tag" style="--proto-color: ${color}">${lbl}</span>
                        <div class="protocol-rank-numbers">
                            <span class="mono protocol-count">${counts[idx].toLocaleString()} pkts</span>
                            <span class="mono protocol-pct">${pct}%</span>
                        </div>
                    </div>
                    <div class="protocol-progress-track">
                        <div class="protocol-progress-bar" style="width: ${pct}%; background-color: ${color}"></div>
                    </div>
                </div>`;
            });
            html += '</div>';
            tableContainer.innerHTML = html;
        }
    }

    function renderTimelineChart(timelineData, metric = "pps") {
        lastTimelineData = timelineData;
        lastTimelineMetric = metric;

        const container = document.getElementById("chart-timeline");
        if (!container) return;

        if (!timelineData || timelineData.length === 0) {
            Plotly.purge(container);
            container.innerHTML = '<div class="empty-state-notice">No timeline events recorded in this capture.</div>';
            return;
        }

        const t = getThemeCfg();
        const times = timelineData.map(b => new Date(b.timestamp * 1000).toISOString().substr(11, 8));
        const values = metric === "pps" ? timelineData.map(b => b.pps) : timelineData.map(b => b.kbps);
        const label = metric === "pps" ? "Packets / Sec (PPS)" : "Throughput (kbps)";
        const lineColor = metric === "pps" ? t.ppsLine : t.kbpsLine;
        const fillColor = metric === "pps" ? t.ppsFill : t.kbpsFill;

        const trace = {
            x: times,
            y: values,
            type: "scatter",
            mode: "lines",
            fill: "tozeroy",
            line: { color: lineColor, width: 2, shape: "spline" },
            fillcolor: fillColor,
            hoverinfo: "x+y",
            name: label,
        };

        const layout = {
            paper_bgcolor: t.paper_bgcolor,
            plot_bgcolor: t.plot_bgcolor,
            font: t.font,
            margin: { l: 45, r: 16, t: 16, b: 32 },
            xaxis: {
                title: { text: "Time (UTC)", font: { size: 10, color: t.font.color } },
                gridcolor: t.gridcolor,
                zerolinecolor: t.zerolinecolor,
                tickfont: { size: 10, color: t.font.color, family: fontStack },
            },
            yaxis: {
                title: { text: label, font: { size: 10, color: t.font.color } },
                gridcolor: t.gridcolor,
                zerolinecolor: t.zerolinecolor,
                tickfont: { size: 10, color: t.font.color, family: fontStack },
            },
        };

        const config = { responsive: true, displayModeBar: false };
        Plotly.react(container, [trace], layout, config);
    }

    return {
        renderProtocolChart,
        renderTimelineChart,
        setTheme,
        getTheme: () => currentTheme,
    };
})();
