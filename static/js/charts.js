/**
 * NetScope Plotly Chart Rendering Engine
 * Implements high-performance, responsive charts with dark theme integration.
 */

const NetScopeCharts = (() => {
    const theme = {
        paper_bgcolor: "transparent",
        plot_bgcolor: "transparent",
        font: { family: "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif", color: "#94a3b8", size: 11 },
        margin: { l: 40, r: 20, t: 30, b: 40 },
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

    function renderProtocolChart(protocolsData, selectedLayer = "transport") {
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
            container.innerHTML = '<div class="empty-state">No protocol data available.</div>';
            if (tableContainer) tableContainer.innerHTML = "";
            return;
        }

        const plotData = [{
            labels: labels,
            values: counts,
            type: "pie",
            hole: 0.55,
            marker: { colors: colors },
            textinfo: "label+percent",
            hoverinfo: "label+value+percent",
            textposition: "inside",
            showlegend: false,
        }];

        const layout = {
            ...theme,
            margin: { l: 20, r: 20, t: 20, b: 20 },
            annotations: [{
                font: { size: 12, color: "#f8fafc", weight: "bold" },
                showarrow: false,
                text: selectedLayer.toUpperCase(),
                x: 0.5,
                y: 0.5,
            }],
        };

        const config = { responsive: true, displayModeBar: false };
        Plotly.react(container, plotData, layout, config);

        // Update mini table
        if (tableContainer) {
            let html = '<table class="data-table"><thead><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr></thead><tbody>';
            labels.forEach((lbl, idx) => {
                html += `<tr>
                    <td><span class="badge badge-proto" style="background:${colors[idx]}20; color:${colors[idx]}">${lbl}</span></td>
                    <td class="mono">${counts[idx].toLocaleString()}</td>
                    <td class="mono">${percentages[idx].toFixed(1)}%</td>
                </tr>`;
            });
            html += '</tbody></table>';
            tableContainer.innerHTML = html;
        }
    }

    function renderTimelineChart(timelineData, metric = "pps") {
        const container = document.getElementById("chart-timeline");
        if (!container) return;

        if (!timelineData || timelineData.length === 0) {
            Plotly.purge(container);
            container.innerHTML = '<div class="empty-state">No timeline events recorded.</div>';
            return;
        }

        const times = timelineData.map(b => new Date(b.timestamp * 1000).toISOString().substr(11, 8));
        const values = metric === "pps" ? timelineData.map(b => b.pps) : timelineData.map(b => b.kbps);
        const label = metric === "pps" ? "Packets / Sec (PPS)" : "Throughput (Kbps)";
        const lineColor = metric === "pps" ? "#38bdf8" : "#34d399";
        const fillColor = metric === "pps" ? "rgba(56, 189, 248, 0.15)" : "rgba(52, 211, 153, 0.15)";

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
            ...theme,
            xaxis: {
                title: "Time (UTC)",
                gridcolor: "#1e293b",
                zerolinecolor: "#1e293b",
                tickfont: { size: 10 },
            },
            yaxis: {
                title: label,
                gridcolor: "#1e293b",
                zerolinecolor: "#1e293b",
                tickfont: { size: 10 },
            },
        };

        const config = { responsive: true, displayModeBar: false };
        Plotly.react(container, [trace], layout, config);
    }

    return {
        renderProtocolChart,
        renderTimelineChart,
    };
})();
