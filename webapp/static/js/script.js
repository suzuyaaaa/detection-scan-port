document.addEventListener("DOMContentLoaded", function () {

    async function loadCharts() {
        try {
            // Fetch data depuis Flask
            const statsResponse = await fetch("/api/stats");
            const stats = await statsResponse.json();

            const typesResponse = await fetch("/api/types");
            const types = await typesResponse.json();

            // 📈 Line Chart (Trafic)
            const ctx1 = document.getElementById("lineChart").getContext("2d");

            new Chart(ctx1, {
                type: "line",
                data: {
                    labels: stats.labels,
                    datasets: [{
                        label: "Alertes par jour",
                        data: stats.values,
                        tension: 0.3,
                        fill: false
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: true
                        }
                    }
                }
            });

            // 🥧 Pie Chart (Types)
            const ctx2 = document.getElementById("pieChart").getContext("2d");

            new Chart(ctx2, {
                type: "pie",
                data: {
                    labels: types.labels,
                    datasets: [{
                        data: types.values
                    }]
                },
                options: {
                    responsive: true
                }
            });

        } catch (error) {
            console.error("Erreur chargement graphiques :", error);
        }
    }

    loadCharts();
});
