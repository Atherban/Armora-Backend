export const generateRecommendations = (breaches) => {
  if (!breaches || breaches.length === 0) {
    return [
      "✅ Your account appears safe — keep monitoring regularly.",
      "🔒 Use strong, unique passwords for each account.",
      "⚙️ Enable two-factor authentication wherever possible.",
      "🕵️ Avoid reusing passwords across platforms.",
    ];
  }

  const critical = breaches.filter(
    (b) => b.Severity === "Critical" || b.Severity === "High"
  );

  const tips = [
    "🧠 Immediately change passwords for all affected accounts.",
    "🔐 Use a password manager to generate unique, secure passwords.",
    "📧 Check if your email is receiving phishing attempts.",
    "🛡️ Enable 2FA on major platforms like Google, Facebook, and LinkedIn.",
  ];

  if (critical.length > 2) {
    tips.push("🚨 Consider creating new accounts for high-risk platforms.");
  }

  return tips;
};
