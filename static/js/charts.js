/**
 * NetScope Plotly Chart Rendering Engine
 * Implements high-performance, responsive charts with dynamic Light and Dark theme integration.
 */

const NetScopeCharts = (() => {
    let currentTheme = "dark";
    let lastProtocolsData = null;
    let lastSelectedLayer = "transport";
    let lastTimelineData = null;
    let lastTimelineMetric = "pps";

    const themes = {
        dark: {
            paper_bgcolor: "transparent",
            plot_bgcolor: "transparent",
            font: { family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif", color: "#94a3b8", size: 11 },
            gridcolor: "#1e293b",
            zerolinecolor: "#334155",
            donutTextColor: "#f8fafc",
            ppsLine: "#38bdf8",
            ppsFill: "rgba(56, 189, 248, 0.14)",
            kbpsLine: "#34d399",
            kbpsFill: "rgba(52, 211, 153, 0.14)",
        },
        light: {
            paper_bgcolor: "transparent",
            plot_bgcolor: "transparent",
            font: { family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif", color: "#475569", size: 11 },
            gridcolor: "#e2e8f0",
            zerolinecolor: "#cbd5e1",
            donutTextColor: "#0f172a",
            ppsLine: "#0284c7",
            ppsFill: "rgba(2, 132, 199, 0.12)",
            kbpsLine: "#059669",
            kbpsFill: "rgba(5, 150, 105, 0.12)",
        },
    };

    const protocolColors = {
        TCP: "#38bdf8",
        UDP: "#c084fc",
        ICMP: "#fbbf24",
        ICMPv6: "#f59e0b",
        ARP: "#34d399",
        DNS: "#f472b6",
        HTTP: "#4ade80",
        TLS: "#0ea5e9",
        IPv4: "#38bdf8",
        IPv6: "#818cf8",
        Other: "#64748b",
        Unknown: "#475569",
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
        const colors = labels.map(l => protocolColors[l] || "#94a3b8");

        if (labels.length === 0 || counts.reduce((a, b) => a + b, 0) === 0) {
            Plotly.purge(container);
            container.innerHTML = '<div class="empty-state">No protocol data available for this layer.</div>';
            if (tableContainer) tableContainer.innerHTML = "";
            return;
        }

        const t = getThemeCfg();

        const plotData = [{
            labels: labels,
            values: counts,
            type: "pie",
            hole: 0.58,
            marker: { colors: colors, line: { color: currentTheme === "dark" ? "#0f172a" : "#ffffff", width: 2 } },
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
                font: { size: 12, color: t.donutTextColor, family: t.font.family, weight: "bold" },
                showarrow: false,
                text: selectedLayer.toUpperCase(),
                x: 0.5,
                y: 0.5,
            }],
        };

        const config = { responsive: true, displayModeBar: false };
        Plotly.react(container, plotData, layout, config);

        // Update mini summary table
        if (tableContainer) {
            let html = '<table class="data-table"><thead><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr></thead><tbody>';
            labels.forEach((lbl, idx) => {
                const color = colors[idx];
                html += `<tr>
                    <td><span class="badge badge-proto" style="background:${color}22; color:${color}; border: 1px solid ${color}44;">${lbl}</span></td>
                    <td class="mono">${counts[idx].toLocaleString()}</td>
                    <td class="mono font-semibold">${percentages[idx].toFixed(1)}%</td>
                </tr>`;
            });
            html += '</tbody></table>';
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
            container.innerHTML = '<div class="empty-state">No timeline events recorded in this capture.</div>';
            return;
        }

        const t = getThemeCfg();
        const times = timelineData.map(b => new Date(b.timestamp * 1000).toISOString().substr(11, 8));
        const values = metric === "pps" ? timelineData.map(b => b.pps) : timelineData.map(b => b.kbps);
        const label = metric === "pps" ? "Packets / Sec (PPS)" : "Throughput (Kbps)";
        const lineColor = metric === "pps" ? t.ppsLine : t.kbpsLine;
        const fillColor = metric === "pps" ? t.ppsFill : t.kbpsFill;

        const trace = {
            x: times,
            y: values,
            type: "scatter",
            mode: "lines+markers",
            fill: "tozeroy",
            line: { color: lineColor, width: 2, shape: "spline" },
            marker: { size: 4, color: lineColor },
            fillcolor: fillColor,
            hoverinfo: "x+y",
            name: label,
        };

        const layout = {
            paper_bgcolor: t.paper_bgcolor,
            plot_bgcolor: t.plot_bgcolor,
            font: t.font,
            margin: { l: 45, r: 20, t: 25, b: 35 },
            xaxis: {
                title: { text: "Time (UTC)", font: { size: 10, color: t.font.color } },
                gridcolor: t.gridcolor,
                zerolinecolor: t.zerolinecolor,
                tickfont: { size: 10, color: t.font.color },
            },
            yaxis: {
                title: { text: label, font: { size: 10, color: t.font.color } },
                gridcolor: t.gridcolor,
                zerolinecolor: t.zerolinecolor,
                tickfont: { size: 10, color: t.font.color },
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
