document.addEventListener("DOMContentLoaded", function () {

    const COLORS = {
        critique: { bg: "rgba(248,81,73,0.15)", border: "rgba(248,81,73,0.8)" },
        moyen:    { bg: "rgba(227,179,65,0.15)", border: "rgba(227,179,65,0.8)" },
        info:     { bg: "rgba(88,166,255,0.15)", border: "rgba(88,166,255,0.8)" },
        line:     { bg: "rgba(88,166,255,0.1)",  border: "rgba(88,166,255,0.8)" },
    };

    const defaultOptions = {
        responsive: true,
        plugins: {
            legend: {
                display: true,
                labels: { color: "#7d8590", font: { size: 12 } }
            },
            tooltip: {
                backgroundColor: "#161b22",
                borderColor: "#1e2d40",
                borderWidth: 1,
                titleColor: "#e6edf3",
                bodyColor: "#7d8590",
            }
        }
    };

    async function fetchJSON(url) {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`Erreur API: ${url} (${res.status})`);
        return res.json();
    }

    async function loadCharts() {
        try {
            const [stats, types] = await Promise.all([
                fetchJSON("/api/stats"),
                fetchJSON("/api/types"),
            ]);

            // 📈 Line Chart (Trafic par jour)
            const ctx1 = document.getElementById("lineChart");
            if (ctx1) {
                new Chart(ctx1.getContext("2d"), {
                    type: "line",
                    data: {
                        labels: stats.labels,
                        datasets: [{
                            label: "Alertes par jour",
                            data: stats.values,
                            tension: 0.4,
                            fill: true,
                            backgroundColor: COLORS.line.bg,
                            borderColor: COLORS.line.border,
                            pointBackgroundColor: COLORS.line.border,
                            pointRadius: 4,
                            pointHoverRadius: 6,
                        }]
                    },
                    options: {
                        ...defaultOptions,
                        scales: {
                            x: {
                                ticks: { color: "#7d8590" },
                                grid:  { color: "rgba(255,255,255,0.05)" }
                            },
                            y: {
                                beginAtZero: true,
                                ticks: { color: "#7d8590" },
                                grid:  { color: "rgba(255,255,255,0.05)" }
                            }
                        }
                    }
                });
            }

            // 🥧 Pie Chart (Types d'alertes)
            const ctx2 = document.getElementById("pieChart");
            if (ctx2) {
                const pieColors = [
                    COLORS.critique.border,
                    COLORS.moyen.border,
                    COLORS.info.border,
                    "rgba(63,185,80,0.8)",
                    "rgba(188,140,255,0.8)",
                ];
                new Chart(ctx2.getContext("2d"), {
                    type: "pie",
                    data: {
                        labels: types.labels,
                        datasets: [{
                            data: types.values,
                            backgroundColor: pieColors.map(c => c.replace("0.8", "0.2")),
                            borderColor: pieColors,
                            borderWidth: 1,
                        }]
                    },
                    options: {
                        ...defaultOptions,
                        plugins: {
                            ...defaultOptions.plugins,
                            legend: {
                                ...defaultOptions.plugins.legend,
                                position: "bottom",
                            }
                        }
                    }
                });
            }

        } catch (error) {
            console.error("Erreur chargement graphiques :", error);
        }
    }

    loadCharts();
});