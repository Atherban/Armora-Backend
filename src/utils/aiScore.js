// utils/scoreUtils.js
export const calculateBaseScore = (data) => {
  let score = 100;

  if (parseFloat(data.memoryUsage) > 85) score -= 15;
  if (data.uptimeHours > 120) score -= 5;
  if (data.threatsDetected.length > 0)
    score -= data.threatsDetected.length * 10;

  return score < 0 ? 0 : score;
};
