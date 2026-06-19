// Wires up a zxcvbn strength meter to any page that includes the
// standard #pw-strength widget. Reads the minimum acceptable score
// from data-min-score on that element so no inline script is needed.
(function () {
  const strengthDiv = document.getElementById("pw-strength");
  if (!strengthDiv) return;

  const minScore = parseInt(strengthDiv.dataset.minScore, 10);
  const pw1 = document.getElementById("id_password1");
  if (!pw1) return;

  const pwProgress = document.getElementById("pw-progress");
  const pwFeedback = document.getElementById("pw-feedback");
  const submitBtn = strengthDiv
    .closest("form")
    .querySelector("button[type=submit]");
  const SCORE_CLASSES = [
    "is-danger",
    "is-danger",
    "is-warning",
    "is-warning",
    "is-success",
  ];

  function updateStrength() {
    if (!pw1.value) {
      strengthDiv.style.display = "none";
      if (submitBtn) submitBtn.disabled = true;
      return;
    }
    const result = zxcvbn(pw1.value);
    const score = result.score;
    strengthDiv.style.display = "";
    pwProgress.value = score;
    SCORE_CLASSES.forEach((cls) => pwProgress.classList.remove(cls));
    pwProgress.classList.add(SCORE_CLASSES[score]);
    const fb = result.feedback;
    const parts = [fb.warning, ...(fb.suggestions || [])].filter(Boolean);
    pwFeedback.textContent = parts.join(" ");
    if (submitBtn) submitBtn.disabled = score < minScore;
  }

  pw1.addEventListener("input", updateStrength);
  updateStrength();
})();
