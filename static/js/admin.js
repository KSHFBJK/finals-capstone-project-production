document.addEventListener("DOMContentLoaded", () => {
  const saveBtn = document.getElementById("saveBtn");
  const csvForm = document.getElementById("csvForm");
  const retrainBtn = document.getElementById("retrainBtn");

  saveBtn.addEventListener("click", async () => {
    const threshold = parseFloat(document.getElementById("threshold").value);
    const domains = document.getElementById("trusted_domains").value
      .split(",")
      .map(d => d.trim())
      .filter(Boolean);
    const mlWeight = parseFloat(document.getElementById("ml_weight").value);

    const res = await fetch("/admin/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ threshold, trusted_domains: domains, ml_weight: mlWeight })
    });
    const data = await res.json();
    document.getElementById("status").textContent = "✅ Settings saved successfully!";
  });

  csvForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(csvForm);
    const res = await fetch("/admin/upload_csv", { method: "POST", body: formData });
    const data = await res.json();
    document.getElementById("modelStatus").textContent =
      data.error ? "⚠️ " + data.error : "✅ Model trained successfully!";
  });

  retrainBtn.addEventListener("click", async () => {
    const res = await fetch("/admin/retrain", { method: "POST" });
    const data = await res.json();
    document.getElementById("modelStatus").textContent =
      data.error ? "⚠️ " + data.error : "✅ Model retrained successfully!";
  });
});
