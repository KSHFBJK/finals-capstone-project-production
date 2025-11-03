document.addEventListener("DOMContentLoaded", async () => {
    const form = document.getElementById("check-form");
    const resultBox = document.getElementById("result-box");
    const verdictEl = document.getElementById("verdict");
    const scoreEl = document.getElementById("score");
    const timeEl = document.getElementById("timestamp");
    const historyList = document.getElementById("history-list");
    const clearBtn = document.getElementById("clear-history");
    const themeToggle = document.getElementById("theme-toggle");
    const html = document.documentElement;

    // === THEME LOAD ===
    async function loadTheme() {
        const res = await fetch("/get_theme");
        const data = await res.json();
        const theme = data.theme || "light";
        html.setAttribute("data-theme", theme);
        themeToggle.textContent = theme === "light" ? "🌙 Dark Mode" : "☀️ Light Mode";
    }

    themeToggle.addEventListener("click", async () => {
        const current = html.getAttribute("data-theme") === "light" ? "dark" : "light";
        await fetch("/toggle_theme", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ theme: current })
        });
        html.setAttribute("data-theme", current);
        themeToggle.textContent = current === "light" ? "🌙 Dark Mode" : "☀️ Light Mode";
    });

    // === HISTORY ===
    async function loadHistory() {
        const res = await fetch("/api/history");
        const data = await res.json();
        historyList.innerHTML = "";
        if (!data.length) {
            historyList.innerHTML = "<li>No history yet.</li>";
            return;
        }
        data.forEach(h => {
            const li = document.createElement("li");
            li.innerHTML = `<strong>${h.verdict}</strong> (${h.final_score})<br>
                            <small>${h.timestamp}</small><br>
                            <em>${h.input.slice(0,120)}...</em>`;
            historyList.appendChild(li);
        });
    }

    clearBtn.addEventListener("click", async () => {
        await fetch("/api/clear_history", { method: "POST" });
        loadHistory();
    });

    // === SCAN ===
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = new FormData(form);
        resultBox.classList.add("hidden");

        const res = await fetch("/api/check", { method: "POST", body: formData });
        const data = await res.json();

        if (data.error) {
            alert("❌ " + data.error);
            return;
        }

        verdictEl.textContent = data.verdict;
        scoreEl.textContent = data.final_score;
        timeEl.textContent = data.timestamp;
        resultBox.classList.remove("hidden");

        loadHistory();
    });

    await loadTheme();
    await loadHistory();
});
