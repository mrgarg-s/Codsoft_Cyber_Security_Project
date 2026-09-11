document.getElementById("quiz").addEventListener("submit", function (e) {
  e.preventDefault();
  const answers = { q1: "b", q2: "c", q3: "b" };
  let score = 0;
  for (const [name, answer] of Object.entries(answers)) {
    if (new FormData(this).get(name) === answer) score++;
  }
  const result = document.getElementById("result");
  result.textContent = `Score: ${score}/3 — ${score === 3 ? "Excellent! You spotted the key phishing defenses." : "Review the checklist and try again."}`;
});
